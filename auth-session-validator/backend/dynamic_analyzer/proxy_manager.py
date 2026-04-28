"""
dynamic_analyzer/proxy_manager.py
───────────────────────────────────
Gestionnaire du proxy MITM (mitmproxy).
Lance, arrête et collecte les données du proxy.
"""

import threading
import asyncio
from typing import Optional


class ProxyManager:
    """
    Wrapper autour de mitmproxy pour capturer le trafic réseau de l'app Android.
    Le téléphone/émulateur doit être configuré pour utiliser ce proxy.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self._running = False
        self.addon: Optional["AuthCapturingAddon"] = None
        self.master = None

    async def start_async(self):
        """
        Démarrage asynchrone du proxy (doit être appelé dans une boucle existante).
        """
        if self._running:
            return

        from mitmproxy.options import Options
        try:
            from mitmproxy.tools.dump import DumpMaster
        except ImportError:
            from mitmproxy.tools.main import dump as DumpMaster

        self.addon = AuthCapturingAddon()
        opts = Options(listen_host=self.host, listen_port=self.port)
        self.master = DumpMaster(opts)
        self.master.addons.add(self.addon)
        self._running = True
        
        print(f"[*] Proxy MITM démarré sur {self.host}:{self.port}")
        try:
            await self.master.run()
        except Exception as e:
            print(f"[!] Erreur Proxy : {e}")
        finally:
            self._running = False

    def start(self) -> dict:
        """Obsolète : utilisé par compatibilité mais ne fait rien ici car géré par main.py."""
        return {"status": "managed_by_main_loop"}

    def stop(self) -> dict:
        """
        Arrête le proxy et retourne les résultats capturés.
        """
        if self.master:
            self.master.shutdown()
        self._running = False
        return self.addon.get_results() if self.addon else {}

    def get_traffic(self) -> dict:
        """Retourne les résultats capturés en temps réel."""
        return self.addon.get_results() if self.addon else {}

    def get_live_results(self) -> dict:
        """Alias pour get_traffic."""
        return self.get_traffic()

    @property
    def is_running(self) -> bool:
        return self._running


class AuthCapturingAddon:
    """
    Addon mitmproxy qui intercepte et analyse le trafic d'authentification.
    """

    def __init__(self):
        self.jwt_tokens = []
        self.http_flows = []
        self.flows = []  # Stocke les flux complets (req + resp)
        self.all_requests_count = 0

    def request(self, flow):
        # On capture absolument TOUT pour être sûr de ne rien rater
        self._capture_flow(flow)
        
        # Redirection intelligente pour InsecureBankv2
        if ":8888" in flow.request.url or "10.0.2.2" in flow.request.url:
            print(f"[*] Redirection Proxy détectée : {flow.request.url}")
            flow.request.host = "127.0.0.1"
            # Si le port a été détourné vers 8080, on le remet sur 8888 pour le serveur réel
            if flow.request.port == 8080:
                flow.request.port = 8888
            
        self.all_requests_count += 1
        
        # 1. Détection HTTP non chiffré
        if flow.request.scheme == "http":
            self.http_flows.append({
                "url": flow.request.url,
                "method": flow.request.method,
                "severity": "MEDIUM"
            })

        # 2. Capture JWT dans les headers
        auth_header = flow.request.headers.get("Authorization", "")
        if "Bearer " in auth_header:
            token = auth_header.replace("Bearer ", "").strip()
            if token not in self.jwt_tokens:
                self.jwt_tokens.append(token)

        # 3. Capture du flux initial (même sans réponse)
        self._capture_flow(flow)

    def _capture_flow(self, flow):
        auth_keywords = ["login", "auth", "token", "signin", "session", "api"]
        is_auth = any(kw in flow.request.url.lower() for kw in auth_keywords)
        
        flow_data = {
            "id": flow.id,
            "method": flow.request.method,
            "url": flow.request.url,
            "request": {
                "headers": dict(flow.request.headers),
                "body": flow.request.get_text() if flow.request.content else ""
            },
            "response": {
                "status_code": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "body": flow.response.get_text() if flow.response.content else ""
            } if flow.response else None,
            "is_auth": is_auth
        }
        
        # Mettre à jour si déjà présent (id unique)
        for i, existing in enumerate(self.flows):
            if existing["id"] == flow.id:
                self.flows[i] = flow_data
                return

        self.flows.append(flow_data)
        if len(self.flows) > 50:
            self.flows.pop(0)

    def response(self, flow):
        # Mettre à jour le flux avec la réponse
        self._capture_flow(flow)

        # 4. Chercher JWT dans le corps de la réponse
        if flow.response and flow.response.content:
            body = flow.response.get_text()
            if "eyJ" in body:
                import re
                tokens = re.findall(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", body)
                for t in tokens:
                    if t not in self.jwt_tokens:
                        self.jwt_tokens.append(t)

    def get_results(self) -> dict:
        return {
            "flows": self.flows,
            "jwt_tokens": self.jwt_tokens,
            "total_requests": self.all_requests_count
        }

proxy_manager = ProxyManager()
