"""
backend/active_validator/token_rotation_tester.py
Tests de rotation des tokens JWT et refresh tokens
"""

import httpx
import asyncio
from typing import Dict, Any, List, Optional


class TokenRotationTester:
    """
    Teste la sécurité de la rotation des tokens.

    Vérifie :
    - Refresh token rotation (one-time use)
    - Access token changement au refresh
    - Détection de réutilisation de refresh token
    - Family tracking (refresh token lineage)
    """

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def test_refresh_token_rotation(
        self,
        refresh_endpoint: str = None,
        initial_credentials: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Teste si les refresh tokens sont à usage unique.

        Args:
            refresh_endpoint: URL du endpoint de refresh
            initial_credentials: {"username": "...", "password": "..."}

        Returns:
            Résultat du test
        """
        result = {
            "test_name": "Refresh Token Rotation",
            "status": "not_tested",
            "is_vulnerable": False,
            "severity": "CRITICAL",
            "summary": "",
            "evidence": [],
            "owasp": "MASVS-AUTH-5",
            "recommendations": []
        }

        if not refresh_endpoint:
            refresh_endpoint = f"{self.base_url}/token/refresh"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Étape 1: Login initial
                if not initial_credentials:
                    initial_credentials = {"username": "admin", "password": "admin@123"}

                login_response = await client.post(
                    f"{self.base_url}/login",
                    data=initial_credentials
                )

                if login_response.status_code != 200:
                    result["status"] = "error"
                    result["summary"] = "Échec du login initial"
                    return result

                # Extraire tokens (format JWT ou session)
                tokens = self._extract_tokens(login_response)
                if not tokens.get("refresh_token"):
                    result["status"] = "not_applicable"
                    result["summary"] = "Aucun refresh token détecté - auth peut-être session-only"
                    return result

                refresh_token_1 = tokens["refresh_token"]
                access_token_1 = tokens.get("access_token", "")

                # Étape 2: Premier refresh
                refresh_response_1 = await client.post(
                    refresh_endpoint,
                    data={"refresh_token": refresh_token_1}
                )

                if refresh_response_1.status_code != 200:
                    result["status"] = "error"
                    result["summary"] = "Échec du premier refresh"
                    return result

                tokens_2 = self._extract_tokens(refresh_response_1)
                refresh_token_2 = tokens_2.get("refresh_token", "")
                access_token_2 = tokens_2.get("access_token", "")

                # Étape 3: Réutiliser l'ancien refresh token (attaque)
                refresh_response_2 = await client.post(
                    refresh_endpoint,
                    data={"refresh_token": refresh_token_1}
                )

                # Vérifier si le serveur accepte le refresh token réutilisé
                if refresh_response_2.status_code == 200:
                    result["is_vulnerable"] = True
                    result["status"] = "VULNÉRABLE"
                    result["summary"] = "Le refresh token peut être réutilisé - pas de rotation"
                    result["evidence"] = [
                        f"Refresh token 1: {refresh_token_1[:50]}...",
                        "Réutilisation acceptée avec succès (HTTP 200)",
                        f"Nouveau refresh token non fourni: {not bool(refresh_token_2)}"
                    ]
                    result["recommendations"] = [
                        "Implémenter la rotation des refresh tokens",
                        "Invalider les refresh tokens après usage",
                        "Maintenir une liste de refresh tokens utilisés"
                    ]
                else:
                    # Vérifier si un nouveau refresh token a été émis
                    if refresh_token_2 and refresh_token_2 != refresh_token_1:
                        result["status"] = "SÉCURISÉ"
                        result["summary"] = "Rotation des refresh tokens implémentée correctement"
                        result["evidence"] = [
                            "Nouveau refresh token émis à chaque refresh",
                            "Ancien refresh token rejeté après usage"
                        ]
                    else:
                        result["status"] = "WARNING"
                        result["summary"] = "Refresh token rejeté mais pas de nouveau token émis"
                        result["evidence"] = [
                            "Le serveur rejette la réutilisation",
                            "Mais ne fournit pas de nouveau refresh token"
                        ]

        except httpx.RequestError as e:
            result["status"] = "error"
            result["summary"] = f"Erreur réseau: {str(e)}"
        except Exception as e:
            result["status"] = "error"
            result["summary"] = f"Erreur inattendue: {str(e)}"

        return result

    async def test_access_token_change_on_refresh(
        self,
        refresh_endpoint: str = None,
        initial_credentials: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Teste si l'access token change à chaque refresh.

        Args:
            refresh_endpoint: URL du endpoint de refresh
            initial_credentials: Credentials pour login

        Returns:
            Résultat du test
        """
        result = {
            "test_name": "Access Token Change on Refresh",
            "status": "not_tested",
            "is_vulnerable": False,
            "severity": "MEDIUM",
            "summary": "",
            "evidence": [],
            "owasp": "MASVS-AUTH-5"
        }

        if not refresh_endpoint:
            refresh_endpoint = f"{self.base_url}/token/refresh"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Login initial
                if not initial_credentials:
                    initial_credentials = {"username": "admin", "password": "admin@123"}

                login_response = await client.post(
                    f"{self.base_url}/login",
                    data=initial_credentials
                )

                if login_response.status_code != 200:
                    result["status"] = "error"
                    result["summary"] = "Échec du login initial"
                    return result

                tokens_1 = self._extract_tokens(login_response)
                access_token_1 = tokens_1.get("access_token", "")

                if not access_token_1:
                    result["status"] = "not_applicable"
                    result["summary"] = "Aucun access token détecté"
                    return result

                # Refresh
                refresh_response = await client.post(
                    refresh_endpoint,
                    data={"refresh_token": tokens_1.get("refresh_token", "")}
                )

                if refresh_response.status_code != 200:
                    result["status"] = "error"
                    result["summary"] = "Échec du refresh"
                    return result

                tokens_2 = self._extract_tokens(refresh_response)
                access_token_2 = tokens_2.get("access_token", "")

                # Comparer les tokens
                if access_token_1 == access_token_2:
                    result["is_vulnerable"] = True
                    result["status"] = "VULNÉRABLE"
                    result["summary"] = "L'access token ne change pas au refresh"
                    result["evidence"] = [
                        "Access token identique avant et après refresh",
                        "Le même token peut être utilisé indéfiniment"
                    ]
                    result["recommendations"] = [
                        "Générer un nouvel access token à chaque refresh",
                        "Changer le jti (JWT ID) à chaque émission"
                    ]
                else:
                    result["status"] = "SÉCURISÉ"
                    result["summary"] = "L'access token change correctement au refresh"
                    result["evidence"] = [
                        "Nouvel access token émis à chaque refresh"
                    ]

        except Exception as e:
            result["status"] = "error"
            result["summary"] = f"Erreur: {str(e)}"

        return result

    async def test_refresh_token_family_tracking(
        self,
        refresh_endpoint: str = None,
        initial_credentials: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Teste si le serveur détecte la réutilisation d'un refresh token d'une autre 'famille'.

        Scenario:
        1. Login → RT1
        2. Refresh RT1 → RT2
        3. Refresh RT1 (à nouveau) → Devrait être rejeté + alerte

        Args:
            refresh_endpoint: URL du endpoint de refresh
            initial_credentials: Credentials pour login

        Returns:
            Résultat du test
        """
        result = {
            "test_name": "Refresh Token Family Tracking",
            "status": "not_tested",
            "is_vulnerable": False,
            "severity": "HIGH",
            "summary": "",
            "evidence": [],
            "owasp": "MASVS-AUTH-5",
            "recommendations": []
        }

        if not refresh_endpoint:
            refresh_endpoint = f"{self.base_url}/token/refresh"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Login
                if not initial_credentials:
                    initial_credentials = {"username": "admin", "password": "admin@123"}

                login_response = await client.post(
                    f"{self.base_url}/login",
                    data=initial_credentials
                )

                tokens = self._extract_tokens(login_response)
                refresh_token_1 = tokens.get("refresh_token")

                if not refresh_token_1:
                    result["status"] = "not_applicable"
                    result["summary"] = "Aucun refresh token détecté"
                    return result

                # Refresh 1: RT1 → RT2
                refresh_1 = await client.post(
                    refresh_endpoint,
                    data={"refresh_token": refresh_token_1}
                )

                if refresh_1.status_code != 200:
                    result["status"] = "error"
                    result["summary"] = "Échec du premier refresh"
                    return result

                tokens_2 = self._extract_tokens(refresh_1)
                refresh_token_2 = tokens_2.get("refresh_token", "")

                # Refresh 2: RT1 (ancien) → Devrait alerter
                refresh_2 = await client.post(
                    refresh_endpoint,
                    data={"refresh_token": refresh_token_1}
                )

                # Vérifier la réponse
                if refresh_2.status_code == 200:
                    result["is_vulnerable"] = True
                    result["status"] = "VULNÉRABLE"
                    result["summary"] = "Le serveur accepte un refresh token d'une autre famille"
                    result["evidence"] = [
                        "RT1 → RT2 (legitimate)",
                        "RT1 → Accepté à nouveau (attaque détectable non implémentée)"
                    ]
                    result["recommendations"] = [
                        "Implémenter le family tracking des refresh tokens",
                        "Révoquer toute la famille si un membre est réutilisé",
                        "Alerter l'utilisateur en cas de réutilisation suspecte"
                    ]
                elif refresh_2.status_code == 401:
                    # Rejeté - vérifier si le serveur invalide RT2 aussi
                    refresh_3 = await client.post(
                        refresh_endpoint,
                        data={"refresh_token": refresh_token_2}
                    )

                    if refresh_3.status_code != 200:
                        result["status"] = "WARNING"
                        result["summary"] = "Réutilisation rejetée mais toute la famille est révoquée"
                        result["evidence"] = [
                            "RT1 réutilisé → Rejeté (OK)",
                            "RT2 → Également révoqué (family revocation)"
                        ]
                    else:
                        result["status"] = "SÉCURISÉ"
                        result["summary"] = "Family tracking partiellement implémenté"
                else:
                    result["status"] = "SÉCURISÉ"
                    result["summary"] = "Réutilisation du refresh token détectée et rejetée"

        except Exception as e:
            result["status"] = "error"
            result["summary"] = f"Erreur: {str(e)}"

        return result

    async def test_concurrent_refresh_attacks(
        self,
        refresh_endpoint: str = None,
        initial_credentials: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Teste les attaques par refresh concurrents (race condition).

        Envoie 2 requêtes de refresh avec le même token en parallèle.

        Returns:
            Résultat du test
        """
        result = {
            "test_name": "Concurrent Refresh Attack",
            "status": "not_tested",
            "is_vulnerable": False,
            "severity": "HIGH",
            "summary": "",
            "evidence": [],
            "owasp": "MASVS-AUTH-5"
        }

        if not refresh_endpoint:
            refresh_endpoint = f"{self.base_url}/token/refresh"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Login
                if not initial_credentials:
                    initial_credentials = {"username": "admin", "password": "admin@123"}

                login_response = await client.post(
                    f"{self.base_url}/login",
                    data=initial_credentials
                )

                tokens = self._extract_tokens(login_response)
                refresh_token = tokens.get("refresh_token")

                if not refresh_token:
                    result["status"] = "not_applicable"
                    result["summary"] = "Aucun refresh token détecté"
                    return result

                # Envoyer 2 requêtes concurrentes
                async def refresh(rt):
                    return await client.post(refresh_endpoint, data={"refresh_token": rt})

                responses = await asyncio.gather(
                    refresh(refresh_token),
                    refresh(refresh_token),
                    return_exceptions=True
                )

                # Analyser les résultats
                success_count = sum(1 for r in responses if isinstance(r, httpx.Response) and r.status_code == 200)

                if success_count == 2:
                    result["is_vulnerable"] = True
                    result["status"] = "VULNÉRABLE"
                    result["summary"] = "Race condition: 2 refresh tokens émis pour le même token"
                    result["evidence"] = [
                        "2 requêtes concurrentes avec le même refresh token",
                        "Les 2 ont réussi → token dupliqué"
                    ]
                    result["recommendations"] = [
                        "Utiliser des locks au niveau du refresh token",
                        "Implémenter une file d'attente pour les refresh",
                        "Utiliser une DB transactionnelle pour le suivi"
                    ]
                elif success_count == 1:
                    result["status"] = "SÉCURISÉ"
                    result["summary"] = "Une seule requête refresh acceptée"
                    result["evidence"] = [
                        "2 requêtes concurrentes",
                        "1 seule acceptée (protection race condition)"
                    ]
                else:
                    result["status"] = "SÉCURISÉ"
                    result["summary"] = "Toutes les requêtes concurrentes rejetées"

        except Exception as e:
            result["status"] = "error"
            result["summary"] = f"Erreur: {str(e)}"

        return result

    def _extract_tokens(self, response: httpx.Response) -> Dict[str, str]:
        """Extrait les tokens d'une réponse HTTP."""
        tokens = {}

        # Try JSON response
        try:
            data = response.json()
            tokens["access_token"] = data.get("access_token", "")
            tokens["refresh_token"] = data.get("refresh_token", "")
            if tokens["access_token"] or tokens["refresh_token"]:
                return tokens
        except:
            pass

        # Try cookies
        cookies = response.cookies
        for cookie in cookies:
            if "access" in cookie.name.lower():
                tokens["access_token"] = cookie.value
            if "refresh" in cookie.name.lower() or "session" in cookie.name.lower():
                tokens["refresh_token"] = cookie.value

        # Try headers
        auth_header = response.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            tokens["access_token"] = auth_header[7:]

        return tokens

    async def run_all_rotation_tests(
        self,
        refresh_endpoint: str = None,
        credentials: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Exécute tous les tests de rotation.

        Returns:
            Résultats combinés
        """
        results = {
            "rotation_test": await self.test_refresh_token_rotation(refresh_endpoint, credentials),
            "access_token_change_test": await self.test_access_token_change_on_refresh(refresh_endpoint, credentials),
            "family_tracking_test": await self.test_refresh_token_family_tracking(refresh_endpoint, credentials),
            "concurrent_attack_test": await self.test_concurrent_refresh_attacks(refresh_endpoint, credentials)
        }

        # Résumé global
        vulnerable_count = sum(1 for r in results.values() if r.get("is_vulnerable"))
        total_tests = len(results)

        results["summary"] = {
            "total_tests": total_tests,
            "vulnerabilities_found": vulnerable_count,
            "overall_status": "CRITICAL" if vulnerable_count >= 2 else "HIGH" if vulnerable_count == 1 else "SECURE"
        }

        return results
