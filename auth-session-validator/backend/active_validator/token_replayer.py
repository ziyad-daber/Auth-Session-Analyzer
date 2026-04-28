"""
active_validator/token_replayer.py
────────────────────────────────────
Test de rejouabilité des tokens JWT.
Vérifie si un token reste valide après logout ou expiration.
C'est un test ACTIF : il envoie de vraies requêtes HTTP au serveur.
"""

import httpx
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional


class TokenReplayer:
    """
    Testeur de rejouabilité des tokens.
    Envoie de vraies requêtes HTTP pour PROUVER l'exploitabilité.
    """

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def test_replay_after_logout(
        self,
        token: str,
        logout_url: str,
        protected_url: str,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Token replay post-logout.

        Étapes :
        1. GET /protected avec le token → doit retourner 200
        2. POST /logout avec le token → logout
        3. GET /protected avec le MÊME token → si 200, vulnérabilité confirmée

        Args:
            token:         Token JWT à tester
            logout_url:    Endpoint de logout (ex: /api/logout)
            protected_url: Endpoint protégé (ex: /api/dashboard)

        Returns:
            Evidence dict avec steps, vulnerability_confirmed, proof
        """
        # TODO: étape 1 — GET protected avec token (vérifier que ça marche)
        # TODO: étape 2 — POST logout
        # TODO: étape 3 — GET protected avec le même token
        # TODO: si status == 200 → vulnerability_confirmed = True
        # TODO: construire la preuve (proof string) avec les status codes
        raise NotImplementedError("test_replay_after_logout — à implémenter")

    async def test_expired_token_replay(
        self,
        token: str,
        protected_url: str,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Token expiré accepté par le serveur.

        Modifier le champ 'exp' du payload pour mettre une date passée,
        re-signer et envoyer au serveur.

        Returns:
            Evidence dict avec expired_token_accepted, severity
        """
        # TODO: décoder le JWT sans vérifier
        # TODO: modifier payload["exp"] = datetime.now() - 24h
        # TODO: re-encoder le token (alg:none ou avec clé vide)
        # TODO: envoyer au serveur et vérifier la réponse
        raise NotImplementedError("test_expired_token_replay — à implémenter")

    async def test_token_from_different_source(
        self,
        static_token: str,
        protected_url: str,
    ) -> Dict[str, Any]:
        """
        SCÉNARIO : Token hardcodé dans le code SOURCE utilisé réellement.

        Tente d'utiliser un token trouvé statiquement pour accéder
        à une ressource protégée → corrélation statique + dynamique confrimée.

        Returns:
            Evidence dict avec attack_successful, correlation_proof
        """
        # TODO: utiliser static_token dans Authorization header
        # TODO: GET protected_url
        # TODO: si 200 → corroborer la découverte statique
        raise NotImplementedError("test_token_from_different_source — à implémenter")
