"""
backend/masvs/auth_type_detector.py
Détecte le type d'authentification utilisé par l'application
"""

import re
from typing import Dict, List, Any, Optional


class AuthTypeDetector:
    """
    Détecte le type d'authentification basé sur l'analyse statique et dynamique.

    Types supportés :
    - JWT (JSON Web Tokens)
    - OAuth2 / OIDC
    - Session-based (cookies, session IDs)
    - Basic Auth
    - API Key
    - Custom Token
    """

    # Patterns pour détection statique
    JWT_PATTERNS = [
        r"eyJ[a-zA-Z0-9_-]{10,}",  # JWT token format
        r"Bearer\s+[a-zA-Z0-9_-]{20,}",  # Bearer token
        r"Authorization.*Bearer",
        r"import.*jwt",  # JWT library imports
        r"from.*jwt.*import",
        r"JWTUtils",
        r"JsonWebToken",
        r"jwt\.decode",
        r"jwt\.encode",
        r"JWT_AUTH",
        r"JWTAuthentication",
    ]

    OAUTH2_PATTERNS = [
        r"oauth2",
        r"oauth.*2",
        r"OAuth2Client",
        r"OAuth2Authorization",
        r"grant_type",
        r"authorization_code",
        r"client_credentials",
        r"refresh_token",
        r"access_token",
        r"token_endpoint",
        r"authorization_endpoint",
        r"redirect_uri",
        r"scope=",
        r"state=",
        r"code=",
        r"PKCE",
        r"code_verifier",
        r"code_challenge",
    ]

    SESSION_PATTERNS = [
        r"session_id",
        r"SESSIONID",
        r"JSESSIONID",
        r"PHPSESSID",
        r"ASP\.NET_SessionId",
        r"Set-Cookie.*session",
        r"Cookie.*session",
        r"HttpSession",
        r"session_start",
        r"session_destroy",
        r"regenerate_session",
        r"session_regenerate",
        r"SharedPreferences.*session",
    ]

    BASIC_AUTH_PATTERNS = [
        r"Basic\s+[a-zA-Z0-9+/=]{10,}",  # Basic auth header
        r"Authorization.*Basic",
        r"HttpURLConnection.*setRequestProperty.*Authorization",
    ]

    API_KEY_PATTERNS = [
        r"api_key",
        r"apikey",
        r"API_KEY",
        r"X-API-Key",
        r"X-Api-Key",
        r"api_secret",
        r"app_secret",
        r"app_key",
    ]

    def __init__(self):
        self.detected_types = []
        self.evidence = []
        self.confidence_scores = {}

    def analyze_static_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Analyse les résultats statiques pour détecter le type d'auth.

        Args:
            findings: Liste des findings statiques

        Returns:
            Dict avec type détecté et confiance
        """
        self.detected_types = []
        self.evidence = []
        self.confidence_scores = {}

        # Analyser chaque finding
        for finding in findings:
            snippet = finding.get("snippet", "")
            file_path = finding.get("file", "")
            finding_type = finding.get("type", "")

            # JWT detection
            if self._matches_patterns(snippet, self.JWT_PATTERNS):
                self._add_evidence("jwt", finding_type, file_path, snippet)

            # OAuth2 detection
            if self._matches_patterns(snippet, self.OAUTH2_PATTERNS):
                self._add_evidence("oauth2", finding_type, file_path, snippet)

            # Session detection
            if self._matches_patterns(snippet, self.SESSION_PATTERNS):
                self._add_evidence("session", finding_type, file_path, snippet)

            # Basic auth detection
            if self._matches_patterns(snippet, self.BASIC_AUTH_PATTERNS):
                self._add_evidence("basic_auth", finding_type, file_path, snippet)

            # API key detection
            if self._matches_patterns(snippet, self.API_KEY_PATTERNS):
                self._add_evidence("api_key", finding_type, file_path, snippet)

        # Calculer les scores de confiance
        self._calculate_confidence_scores()

        # Déterminer le type principal
        primary_type = self._determine_primary_type()

        return {
            "primary_auth_type": primary_type,
            "all_detected_types": list(set(self.detected_types)),
            "confidence": self.confidence_scores,
            "evidence": self.evidence,
            "is_hybrid": len(set(self.detected_types)) > 1
        }

    def analyze_dynamic_traffic(self, traffic_flows: List[Dict]) -> Dict[str, Any]:
        """
        Analyse le trafic dynamique pour détecter le type d'auth.

        Args:
            traffic_flows: Liste des flux HTTP capturés

        Returns:
            Dict avec type détecté et preuves dynamiques
        """
        dynamic_evidence = []
        dynamic_types = set()

        for flow in traffic_flows:
            request = flow.get("request", {})
            response = flow.get("response", {})
            url = flow.get("url", "")

            # Analyser les headers de requête
            headers = request.get("headers", {})
            auth_header = headers.get("Authorization", "")

            if auth_header.startswith("Bearer "):
                dynamic_types.add("jwt")
                dynamic_evidence.append({
                    "type": "jwt",
                    "source": "Authorization header",
                    "value": "Bearer token detected",
                    "url": url
                })

            if auth_header.startswith("Basic "):
                dynamic_types.add("basic_auth")
                dynamic_evidence.append({
                    "type": "basic_auth",
                    "source": "Authorization header",
                    "value": "Basic auth detected",
                    "url": url
                })

            # Analyser les cookies
            cookie_header = headers.get("Cookie", "")
            if "session" in cookie_header.lower() or "JSESSIONID" in cookie_header:
                dynamic_types.add("session")
                dynamic_evidence.append({
                    "type": "session",
                    "source": "Cookie header",
                    "value": "Session cookie detected",
                    "url": url
                })

            # Analyser la réponse
            response_headers = response.get("headers", {})
            set_cookie = response_headers.get("Set-Cookie", "")

            if "session" in set_cookie.lower():
                dynamic_types.add("session")
                dynamic_evidence.append({
                    "type": "session",
                    "source": "Set-Cookie header",
                    "value": "Session cookie set by server",
                    "url": url
                })

            # Analyser le body de requête
            body = request.get("body", "")
            if "grant_type" in body:
                dynamic_types.add("oauth2")
                dynamic_evidence.append({
                    "type": "oauth2",
                    "source": "Request body",
                    "value": "OAuth2 grant_type detected",
                    "url": url
                })

            if "access_token" in body or "refresh_token" in body:
                dynamic_types.add("oauth2")
                dynamic_evidence.append({
                    "type": "oauth2",
                    "source": "Request body",
                    "value": "OAuth2 token exchange detected",
                    "url": url
                })

        return {
            "detected_types": list(dynamic_types),
            "evidence": dynamic_evidence
        }

    def analyze_endpoints(self, endpoints: List[Dict]) -> Dict[str, Any]:
        """
        Analyse les endpoints détectés pour confirmer le type d'auth.

        Args:
            endpoints: Liste des endpoints extraits

        Returns:
            Dict avec indices basés sur les endpoints
        """
        endpoint_evidence = []
        endpoint_types = set()

        auth_endpoints = endpoints.get("auth_endpoints", [])

        for endpoint in auth_endpoints:
            url = endpoint.get("url", "")
            method = endpoint.get("method", "")

            # OAuth2 endpoints
            if any(p in url.lower() for p in ["/oauth/", "/oauth2/", "/authorize", "/token"]):
                endpoint_types.add("oauth2")
                endpoint_evidence.append({
                    "type": "oauth2",
                    "evidence": f"OAuth2 endpoint detected: {url}"
                })

            # JWT-related endpoints
            if any(p in url.lower() for p in ["/jwt/", "/token/refresh", "/api/token"]):
                endpoint_types.add("jwt")
                endpoint_evidence.append({
                    "type": "jwt",
                    "evidence": f"JWT endpoint detected: {url}"
                })

            # Session endpoints
            if any(p in url.lower() for p in ["/login", "/logout", "/session"]):
                endpoint_types.add("session")
                endpoint_evidence.append({
                    "type": "session",
                    "evidence": f"Session endpoint detected: {url}"
                })

        return {
            "detected_types": list(endpoint_types),
            "evidence": endpoint_evidence
        }

    def _matches_patterns(self, text: str, patterns: List[str]) -> bool:
        """Vérifie si le texte correspond à l'un des patterns."""
        if not text:
            return False
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _add_evidence(self, auth_type: str, finding_type: str, file_path: str, snippet: str):
        """Ajoute une preuve pour un type d'authentification."""
        self.detected_types.append(auth_type)
        self.evidence.append({
            "type": auth_type,
            "finding_type": finding_type,
            "file": file_path,
            "snippet": snippet[:200] if len(snippet) > 200 else snippet
        })

    def _calculate_confidence_scores(self):
        """Calcule les scores de confiance pour chaque type détecté."""
        type_counts = {}
        for auth_type in self.detected_types:
            type_counts[auth_type] = type_counts.get(auth_type, 0) + 1

        for auth_type, count in type_counts.items():
            # Score basé sur le nombre de preuves
            if count >= 5:
                self.confidence_scores[auth_type] = 0.95
            elif count >= 3:
                self.confidence_scores[auth_type] = 0.80
            elif count >= 2:
                self.confidence_scores[auth_type] = 0.65
            else:
                self.confidence_scores[auth_type] = 0.40

    def _determine_primary_type(self) -> Optional[str]:
        """Détermine le type d'authentification principal."""
        if not self.confidence_scores:
            return None

        # Priorité: OAuth2 > JWT > Session > Basic > API Key
        priority_order = ["oauth2", "jwt", "session", "basic_auth", "api_key"]

        for auth_type in priority_order:
            if auth_type in self.confidence_scores and self.confidence_scores[auth_type] >= 0.65:
                return auth_type

        # Retourner le type avec le meilleur score
        return max(self.confidence_scores, key=self.confidence_scores.get)

    def get_masvs_requirements(self, auth_type: str) -> List[str]:
        """
        Retourne les exigences MASVS applicables pour un type d'auth.

        Args:
            auth_type: Type d'authentification

        Returns:
            Liste des IDs d'exigences MASVS
        """
        from .masvs_database import AUTH_TYPE_REQUIREMENTS
        return AUTH_TYPE_REQUIREMENTS.get(auth_type, AUTH_TYPE_REQUIREMENTS["all"])
