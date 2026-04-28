"""
report_generator/evidence_collector.py
────────────────────────────────────────
Collecte et formate les preuves d'exploit pour le rapport.
Transforme les résultats bruts en preuves lisibles et vérifiables.
"""

from typing import Dict, Any, List


class EvidenceCollector:
    """
    Agrège et formate les preuves de toutes les phases d'analyse.
    Chaque preuve doit être reproductible et vérifiable.
    """

    def collect_all(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Collecte toutes les preuves disponibles depuis les résultats d'analyse.

        Returns:
            Liste de preuves structurées : [{"type", "severity", "proof_text", "reproduction_steps"}, ...]
        """
        evidences = []
        evidences.extend(self._collect_static_evidence(analysis_results.get("static", {})))
        evidences.extend(self._collect_dynamic_evidence(analysis_results.get("dynamic", {})))
        evidences.extend(self._collect_active_evidence(analysis_results.get("validation", {})))
        evidences.extend(self._collect_correlation_evidence(analysis_results.get("correlations", [])))
        return evidences

    def _collect_static_evidence(self, static: dict) -> List[Dict[str, Any]]:
        """
        Formate les preuves statiques (secrets trouvés dans le code).

        Format de preuve :
        - Fichier source, numéro de ligne
        - Extrait du code (masqué partiellement)
        - Impact potentiel
        """
        # TODO: pour chaque secret finding, créer une preuve avec:
        #   - fichier:ligne
        #   - extrait du code (token masqué après les 10 premiers chars)
        #   - "reproduction: décompiler l'APK avec jadx et chercher ce pattern"
        raise NotImplementedError("_collect_static_evidence — à implémenter")

    def _collect_dynamic_evidence(self, dynamic: dict) -> List[Dict[str, Any]]:
        """
        Formate les preuves dynamiques (trafic intercepté).

        Format de preuve :
        - URL interceptée
        - Headers de la requête (token visible)
        - "reproduction: configurer proxy mitmproxy sur port 8888"
        """
        # TODO: pour chaque JWT intercepté, créer une preuve avec la requête HTTP
        # TODO: pour chaque flux HTTP non chiffré, montrer l'URL et les données exposées
        raise NotImplementedError("_collect_dynamic_evidence — à implémenter")

    def _collect_active_evidence(self, validation: dict) -> List[Dict[str, Any]]:
        """
        Formate les preuves des tests actifs (exploits confirmés).

        Format de preuve :
        - Requête HTTP envoyée (avec token forgé)
        - Réponse HTTP reçue (code + body partiel)
        - Étapes de reproduction
        """
        # TODO: pour chaque test actif avec vulnerability_confirmed == True
        # TODO: construire une preuve avec les steps et les status codes HTTP
        raise NotImplementedError("_collect_active_evidence — à implémenter")

    def _collect_correlation_evidence(self, correlations: list) -> List[Dict[str, Any]]:
        """
        Formate les preuves de corrélation (trouvé statiquement ET dynamiquement).

        Format de preuve :
        - Source statique (fichier)
        - Confirmation dynamique (URL)
        - "Ce token trouvé dans le code est le même que celui intercepté sur le réseau"
        """
        # TODO: pour chaque corrélation, combiner les preuves statique et dynamique
        raise NotImplementedError("_collect_correlation_evidence — à implémenter")

    @staticmethod
    def format_http_request(method: str, url: str, headers: dict, body: str = "") -> str:
        """
        Formate une requête HTTP de manière lisible pour le rapport.

        Returns:
            Chaîne de texte formatée comme une vraie requête HTTP
        """
        # TODO: construire la représentation HTTP/1.1 standard
        # Exemple :
        # POST /api/login HTTP/1.1
        # Host: 10.0.2.2:8888
        # Authorization: Bearer eyJ...
        # Content-Type: application/json
        #
        # {"username": "admin", "password": "password"}
        raise NotImplementedError("format_http_request — à implémenter")

    @staticmethod
    def mask_token(token: str, visible_chars: int = 20) -> str:
        """
        Masque partiellement un token pour l'affichage dans le rapport.
        Exemple : eyJhbGciOiJIUzI1NiJ9... [MASKED]

        Returns:
            Token partiellement masqué
        """
        # TODO: afficher les N premiers chars + "... [MASKED]"
        raise NotImplementedError("mask_token — à implémenter")
