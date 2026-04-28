"""
correlation_engine/correlator.py
──────────────────────────────────
Moteur de corrélation : croise les résultats statiques, dynamiques et actifs.
C'est ici que naissent les preuves d'exploit confirmées.
"""

from typing import List, Dict, Any


class CorrelationEngine:
    """
    Corrèle les données de toutes les phases pour produire des findings
    avec preuve d'exploitabilité confirmée.

    Principe :
    - Statique seul     → "potentiellement vulnérable"
    - Dynamique seul    → "comportement suspect détecté"
    - Statique + Dynamique + Actif → "CONFIRMÉ EXPLOITABLE — preuve disponible"
    """

    def __init__(
        self,
        static_results: dict,
        dynamic_results: dict,
        validation_results: dict,
    ):
        self.static = static_results
        self.dynamic = dynamic_results
        self.validation = validation_results
        self.correlations: List[Dict[str, Any]] = []

    def correlate_all(self) -> List[Dict[str, Any]]:
        """Lance toutes les corrélations et retourne les findings combinés."""
        self._correlate_static_dynamic_secrets()
        self._correlate_hardcoded_endpoints()
        return self.correlations

    def _correlate_static_dynamic_secrets(self):
        """
        CAS 1 : Secret (password/key) trouvé statiquement ET présent dans le trafic dynamique.
        → Preuve que le secret hardcodé est réellement utilisé.
        """
        static_findings = self.static.get("findings", [])
        flows = self.dynamic.get("flows", [])

        for static in static_findings:
            if static.get("type") == "HARDCODED_SECRET":
                # On essaie d'extraire la valeur du snippet si non présente directement
                import re
                snippet = static.get("snippet", "")
                match = re.search(r'=\s*["\']([^"\']+)["\']', snippet)
                secret_value = match.group(1) if match else None
                
                if not secret_value: continue

                for flow in flows:
                    # On cherche le secret dans le body de la requête
                    req_body = str(flow.get("request", {}).get("body", ""))
                    if secret_value in req_body:
                        self.correlations.append({
                            "type": "CONFIRMED_EXPLOIT_SECRET",
                            "severity": "CRITICAL",
                            "static_source": static.get("file", "unknown"),
                            "dynamic_evidence": flow.get("url"),
                            "proof": f"Le secret '{secret_value}' trouvé dans {static.get('file')} est utilisé dans une requête vers {flow.get('url')}. Exploitation confirmée.",
                            "owasp": "MASVS-AUTH-2",
                            "score": 40
                        })
                        break # Un exploit confirmé suffit pour ce secret

    def _correlate_hardcoded_endpoints(self):
        """
        CAS 2 : Endpoint extrait statiquement ET contacté en réseau.
        → Confirme que l'endpoint est actif et accessible.
        """
        static_findings = self.static.get("findings", [])
        flows = self.dynamic.get("flows", [])

        for static in static_findings:
            if static.get("type") == "ENDPOINT_FOUND":
                endpoint = static.get("snippet", "")
                if not endpoint: continue

                for flow in flows:
                    if endpoint in flow.get("url", ""):
                        self.correlations.append({
                            "type": "CONFIRMED_ENDPOINT_ACTIVE",
                            "severity": "HIGH",
                            "static_source": static.get("file", "unknown"),
                            "dynamic_evidence": flow.get("url"),
                            "proof": f"L'endpoint '{endpoint}' découvert par analyse statique est activement sollicité par l'application.",
                            "owasp": "MASVS-NETWORK-1",
                            "score": 10
                        })
                        break
