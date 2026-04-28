"""
backend/dynamic_analyzer/frida_manager.py
────────────────────────────────────────────
Gestionnaire d'instrumentation dynamique via Frida (Version Chirurgicale).
"""

import frida
import subprocess
import threading
from typing import List, Dict, Any, Optional

class FridaManager:
    def __init__(self):
        self.device: Optional[frida.core.Device] = None
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.results: List[Dict[str, Any]] = []
        self._is_running = False

    @property
    def is_connected(self) -> bool:
        return self._is_running

    def _ensure_device(self):
        """S'assure que la connexion au device est active et fonctionnelle."""
        is_valid = False
        try:
            if self.device:
                self.device.enumerate_processes()
                is_valid = True
        except:
            is_valid = False

        if not is_valid:
            print("[FRIDA] Connexion perdue ou inexistante. Tentative de reconnexion via TCP...")
            self.device = None
            
            # On s'assure que le serveur tourne et que le port est forwardé
            self._bootstrap_frida()
            
            try:
                # On utilise une connexion distante pour bypasser le check "jailed"
                # qui arrive parfois sur les émulateurs via USB.
                mgr = frida.get_device_manager()
                self.device = mgr.add_remote_device("127.0.0.1:27042")
                print("[FRIDA] Connecté via Remote TCP (127.0.0.1:27042)")
            except Exception as e:
                print(f"[FRIDA] Échec connexion TCP: {e}. Repli sur USB...")
                try:
                    self.device = frida.get_usb_device(timeout=2)
                except Exception as e2:
                    print(f"[FRIDA] Échec critique : {e2}")
                    raise Exception("Impossible de se connecter à Frida.")

        # Configuration des tunnels
        self._setup_tunnels()

    def _setup_tunnels(self):
        """Configure les tunnels ADB (forward pour Frida, reverse pour le lab)."""
        try:
            subprocess.run(["adb", "-s", "emulator-5554", "root"], capture_output=True)
            # Port forward pour le serveur Frida lui-même
            subprocess.run(["adb", "-s", "emulator-5554", "forward", "tcp:27042", "tcp:27042"], capture_output=True)
            # Reverse pour le reste
            ports = [8888, 8000, 8080]
            for port in ports:
                subprocess.run(["adb", "-s", "emulator-5554", "reverse", f"tcp:{port}", f"tcp:{port}"], capture_output=True)
        except:
            pass

    def _bootstrap_frida(self):
        """Tente de lancer le frida-server sur l'appareil via ADB et configure les tunnels."""
        print("[FRIDA] Auto-démarrage du serveur...")
        try:
            # 1. Passer ADB en root
            subprocess.run(["adb", "-s", "emulator-5554", "root"], capture_output=True)
            
            # 2. Vérifier si frida-server tourne déjà
            check = subprocess.run(["adb", "-s", "emulator-5554", "shell", "pgrep frida-server"], capture_output=True, text=True)
            if check.stdout.strip():
                print("[FRIDA] Le serveur tourne déjà.")
                return

            # 3. Lancement avec écoute sur toutes les interfaces
            cmd = "chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server -l 0.0.0.0:27042 &"
            subprocess.Popen(["adb", "-s", "emulator-5554", "shell", cmd], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
            
            import time
            time.sleep(2)
            print("[FRIDA] Bootstrap terminé.")
        except Exception as e:
            print(f"[FRIDA] Erreur bootstrap: {e}")

    def attach(self, package_name: str):
        """Alias pour start_analysis, utilisé par le setup_manager."""
        return self.start_analysis(package_name)

    def start_analysis(self, package_name: str):
        if self._is_running:
            self.stop_analysis()

        self._ensure_device()
        
        try:
            # On force l'arrêt de l'application pour un démarrage propre (Spawn)
            subprocess.run(["adb", "shell", f"am force-stop {package_name}"], capture_output=True)
            
            try:
                print(f"[FRIDA] Tentative d'attachement à {package_name}...")
                self.session = self.device.attach(package_name)
            except:
                print(f"[FRIDA] Attach échoué, lancement (Spawn) de {package_name}")
                pid = self.device.spawn([package_name])
                self.session = self.device.attach(pid)
                
                self.script = self.session.create_script(self._get_combined_script())
                self.script.on('message', self._on_message)
                self.script.load()
                print("[FRIDA] Script chargé, reprise de l'exécution (Resume)")
                self.device.resume(pid)
            self._is_running = True
            self.results.append({
                "type": "SYSTEM",
                "message": f"Frida : Analyse active pour {package_name}",
                "severity": "INFO",
                "timestamp": "now"
            })
        except Exception as e:
            raise e

    def _on_message(self, message, data):
        if message['type'] == 'send':
            self.results.append(message['payload'])
        elif message['type'] == 'error':
            error_msg = message.get('stack', message.get('description', 'Erreur inconnue'))
            print(f"[FRIDA-ERR] {error_msg}")
            self.results.append({
                "type": "SYSTEM",
                "severity": "CRITICAL",
                "message": f"FRIDA ERROR: {error_msg.split('\\n')[0]}"
            })

    def get_results(self) -> List[Dict[str, Any]]:
        return self.results

    def stop_analysis(self):
        if self.session:
            try:
                self.session.detach()
            except:
                pass
        self._is_running = False
        self.session = None
        self.script = None

    def _get_combined_script(self) -> str:
        return """
(function() {
    function start_hooks() {
        if (typeof Java === 'undefined' || !Java.available) {
            setTimeout(start_hooks, 500);
            return;
        }
        
        Java.perform(function() {
            send({ type: "SYSTEM", message: "🚀 AUDIT RÉSEAU TOTAL ACTIVÉ", severity: "INFO" });

        // 1. Interception Apache HttpClient (utilisé par InsecureBank)
        try {
            var AbstractHttpClient = Java.use("org.apache.http.impl.client.AbstractHttpClient");
            AbstractHttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest").implementation = function(request) {
                var uri = request.getURI().toString();
                send({ type: "FRIDA_FLOW", message: "🔍 Interception HttpClient : " + uri, severity: "HIGH" });
                
                // Redirection forcée vers notre proxy
                var newUri = uri.replace(":8888", ":8080").replace("localhost", "10.0.2.2").replace("127.0.0.1", "10.0.2.2");
                if (uri.indexOf("10.0.2.2") === -1 && uri.indexOf("8888") !== -1) {
                    newUri = "http://10.0.2.2:8080" + uri.substring(uri.indexOf(":8888") + 5);
                }
                
                request.setURI(Java.use("java.net.URI").create(newUri));
                return this.execute(request);
            };
        } catch(e) { send({ type: "SYSTEM", message: "[-] HttpClient non trouvé", severity: "INFO" }); }

        // 2. Interception HttpURLConnection (Standard Android)
        try {
            var URL = Java.use("java.net.URL");
            URL.$init.overload('java.lang.String').implementation = function(url) {
                var newUrl = url;
                if (url.indexOf(":8888") !== -1) {
                    newUrl = url.replace(":8888", ":8080").replace("localhost", "10.0.2.2").replace("127.0.0.1", "10.0.2.2");
                    send({ type: "FRIDA_FLOW", message: "🔀 Redirection URL : " + url + " -> " + newUrl, severity: "HIGH" });
                }
                return this.$init(newUrl);
            };
        } catch(e) {}

        // 3. Capture des Credentials LoginActivity (Spécifique InsecureBank)
        try {
            var LoginActivity = Java.use("com.android.insecurebankv2.LoginActivity");
            LoginActivity.performlogin.implementation = function() {
                var user = this.Username_Text.value.getText().toString();
                var pass = this.Password_Text.value.getText().toString();
                send({ type: "AUTH_CAPTURE", severity: "CRITICAL", message: "🔑 IDENTIFIANTS CAPTURÉS : " + user + " / " + pass });
                return this.performlogin();
            };
        } catch(e) {}
    });
    }
    
    send({ type: "SYSTEM", message: "🛰️ LIAISON FRIDA : Initialisation...", severity: "INFO" });
    start_hooks();
})();
"""


frida_manager = FridaManager()
