"""
backend/dynamic_analyzer/setup_manager.py
──────────────────────────────────────────
Automatisation complète de l'environnement de test (ADB, Frida, Proxy, APK).
"""

import os
import subprocess
import time
import threading
from typing import Generator, Dict, Any

class SetupManager:
    def __init__(self):
        self.steps = []
        self.is_busy = False

    def auto_setup(self, apk_path: str = None, package_name: str = None) -> Generator[Dict[str, Any], None, None]:
        """Générateur de progression pour le setup automatique."""
        if self.is_busy:
            yield {"step": "Système", "status": "warning", "message": "Setup déjà en cours. Veuillez patienter..."}
            # return  # Optionnel: on peut laisser le stream ouvert pour voir la fin

        self.is_busy = True
        try:
            # 1. Vérification ADB
            yield {"step": "Émulateur", "status": "pending", "message": "Recherche d'appareils..."}
            devices = self._get_adb_devices()
            if not devices:
                yield {"step": "Émulateur", "status": "error", "message": "Aucun émulateur détecté. Lancez Android Studio."}
                return
            yield {"step": "Émulateur", "status": "ok", "message": f"Appareil détecté : {devices[0]}"}

            # 2. ADB Root & Tunnels
            yield {"step": "Connectivité", "status": "pending", "message": "Configuration des tunnels..."}
            subprocess.run(["adb", "root"], capture_output=True, timeout=5)
            # Reverse tunnels pour que l'émulateur accède au host
            ports = [8888, 8000, 8080]
            for port in ports:
                subprocess.run(["adb", "reverse", f"tcp:{port}", f"tcp:{port}"], capture_output=True)
            yield {"step": "Connectivité", "status": "ok", "message": "Tunnels ADB Reverse configurés (8888, 8000)."}

            # 3. Frida Server
            yield {"step": "Frida Server", "status": "pending", "message": "Démarrage du serveur Frida..."}
            if self._start_frida_server():
                yield {"step": "Frida Server", "status": "ok", "message": "Frida Server est actif sur l'appareil."}
            else:
                yield {"step": "Frida Server", "status": "error", "message": "Impossible de lancer frida-server."}

            # 4. Proxy Configuration
            yield {"step": "Proxy", "status": "pending", "message": "Configuration du proxy système..."}
            subprocess.run(["adb", "shell", "settings", "put", "global", "http_proxy", "10.0.2.2:8080"], timeout=5)
            yield {"step": "Proxy", "status": "ok", "message": "Proxy configuré sur 10.0.2.2:8080"}

            # 5. APK Installation & Launch
            if apk_path and package_name:
                yield {"step": "Application", "status": "pending", "message": f"Installation de {package_name}..."}
                subprocess.run(["adb", "install", "-r", apk_path], capture_output=True, timeout=30)
                yield {"step": "Application", "status": "pending", "message": "Lancement & Hook Frida..."}
                subprocess.run(["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"], capture_output=True)
                time.sleep(3)
                from dynamic_analyzer.frida_manager import frida_manager
                frida_manager.attach(package_name)
                yield {"step": "Application", "status": "ok", "message": "Application lancée et Frida attaché."}

            yield {"status": "completed", "message": "Environnement prêt pour l'analyse dynamique."}
        except Exception as e:
            yield {"step": "Erreur Fatale", "status": "error", "message": str(e)}
        finally:
            self.is_busy = False

    def _get_adb_devices(self):
        try:
            res = subprocess.run(["adb", "devices"], capture_output=True, text=True)
            lines = res.stdout.strip().split("\n")[1:]
            return [l.split("\t")[0] for l in lines if l.strip()]
        except: return []

    def _start_frida_server(self):
        try:
            # Vérifier si déjà lancé
            check = subprocess.run(["adb", "shell", "pgrep frida-server"], capture_output=True, text=True)
            if check.stdout.strip(): return True

            # Sinon lancer (doit être dans /data/local/tmp)
            subprocess.Popen(["adb", "shell", "chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server &"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            return True
        except: return False

    def reset_proxy(self):
        """Désactive le proxy sur l'émulateur."""
        try:
            subprocess.run(["adb", "shell", "settings", "put", "global", "http_proxy", ":0"], timeout=5)
        except: pass

setup_manager = SetupManager()
