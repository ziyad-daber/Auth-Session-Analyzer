"""
active_validator/session_validator.py
───────────────────────────────────────
Validation active des sessions côté serveur.
Teste : invalidation après logout, timeout de session, fixation de session.
"""

import httpx
import asyncio
from typing import Dict, Any, Optional


class SessionValidator:
    """
    Valide le comportement des sessions côté serveur via de vraies requêtes HTTP.
    """

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def test_session_invalidation(
        self,
        login_url: str,
        logout_url: str,
        protected_url: str,
        credentials: dict,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO COMPLET : Login → Accès protégé → Logout → Accès protégé (doit échouer).

        Args:
            credentials: {"username": "...", "password": "..."}

        Returns:
            Evidence avec session_invalidated, steps détaillés
        """
        # TODO: POST /login → récupérer le cookie/token de session
        # TODO: GET /protected → vérifier que la session fonctionne
        # TODO: POST /logout
        # TODO: GET /protected avec la même session → doit être 401/403
        raise NotImplementedError("test_session_invalidation — à implémenter")

    async def test_session_fixation(
        self,
        login_url: str,
        protected_url: str,
        credentials: dict,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Session fixation.
        Vérifier que l'ID de session change après le login (il doit changer).

        Returns:
            Evidence avec session_id_before, session_id_after, vulnerability_confirmed
        """
        # TODO: GET /login page → noter le session cookie
        # TODO: POST /login avec ce cookie
        # TODO: vérifier que le cookie a changé après login
        raise NotImplementedError("test_session_fixation — à implémenter")

    async def test_concurrent_sessions(
        self,
        login_url: str,
        protected_url: str,
        credentials: dict,
        session_count: int = 3,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Sessions parallèles non limitées.
        Ouvrir N sessions simultanées et vérifier si le serveur les accepte toutes.

        Returns:
            Evidence avec sessions_allowed, vulnerability_confirmed si > 1 session active
        """
        # TODO: créer session_count sessions en parallèle avec asyncio.gather
        # TODO: vérifier que toutes les sessions fonctionnent simultanément
        raise NotImplementedError("test_concurrent_sessions — à implémenter")

    async def test_session_timeout(
        self,
        protected_url: str,
        token: str,
        wait_seconds: int = 0,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Absence de timeout de session.
        Note : On ne peut pas attendre longtemps, mais on peut vérifier l'expiration du JWT.

        Returns:
            Evidence avec timeout_enforced
        """
        # TODO: vérifier si le JWT a un exp
        # TODO: si exp présent, calculer la durée de validité
        # TODO: signaler si la durée est > 24h (excessive)
        raise NotImplementedError("test_session_timeout — à implémenter")
