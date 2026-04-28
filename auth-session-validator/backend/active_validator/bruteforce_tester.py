"""
active_validator/bruteforce_tester.py
───────────────────────────────────────
Test de la protection contre les attaques par force brute.
Vérifie : account lockout, rate limiting, CAPTCHA, delays.
"""

import httpx
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional


# Mots de passe faibles courants pour le test
COMMON_PASSWORDS: List[str] = [
    "password", "123456", "admin", "letmein", "qwerty",
    "password123", "abc123", "111111", "iloveyou", "master",
    "sunshine", "princess", "welcome", "shadow", "monkey",
]


class BruteforceTester:
    """
    Teste la robustesse de la protection contre les attaques par force brute.
    """

    def __init__(self, timeout: int = 10, delay_between_requests: float = 0.3):
        self.timeout = timeout
        self.delay = delay_between_requests

    async def test_lockout_policy(
        self,
        login_url: str,
        username: str,
        max_attempts: int = 5,
    ) -> Dict[str, Any]:
        results = []
        protection_detected = False
        vulnerability_confirmed = True

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for i in range(max_attempts):
                start_time = datetime.now()
                try:
                    resp = await client.post(login_url, data={"username": username, "password": f"wrong_{i}"})
                    duration = (datetime.now() - start_time).total_seconds()
                    
                    results.append({
                        "attempt": i + 1,
                        "status": resp.status_code,
                        "duration": round(duration, 3),
                        "response": resp.text[:100]
                    })

                    if resp.status_code in [429, 423]:
                        protection_detected = True
                        vulnerability_confirmed = False
                        break
                except httpx.ConnectError:
                    results.append({"attempt": i + 1, "error": "Impossible de se connecter au serveur cible (Port fermé ?)"})
                    vulnerability_confirmed = False
                    break
                except Exception as e:
                    results.append({"attempt": i + 1, "error": str(e)})
                    vulnerability_confirmed = False
                    break
                await asyncio.sleep(self.delay)

        summary = "Protection détectée (Lockout/Rate-limiting)." if protection_detected else "Aucun blocage détecté après 5 tentatives."
        if any("error" in r for r in results):
            summary = "Erreur lors de la tentative d'attaque : " + results[-1].get("error", "Erreur inconnue")

        return {
            "vulnerability_confirmed": vulnerability_confirmed and not protection_detected and len(results) == max_attempts,
            "protection_detected": protection_detected,
            "attempts": results,
            "summary": summary
        }

    async def test_rate_limiting(
        self,
        endpoint_url: str,
        requests_per_second: int = 10,
        duration_seconds: int = 5,
    ) -> Dict[str, Any]:
        """
        Envoie une rafale de requêtes et vérifie si le rate limiting s'active.

        Returns:
            Evidence avec rate_limited, throttling_threshold
        """
        # TODO: lancer requests_per_second requêtes/seconde pendant duration_seconds
        # TODO: compter les 429 reçus
        # TODO: calculer le seuil de déclenchement
        raise NotImplementedError("test_rate_limiting — à implémenter")

    async def test_username_enumeration(
        self,
        login_url: str,
        valid_username: str,
        invalid_username: str = "non_existent_user_999",
    ) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # 1. Test avec utilisateur valide
                resp_valid = await client.post(login_url, data={"username": valid_username, "password": "wrong_password"})
                msg_valid = resp_valid.text

                # 2. Test avec utilisateur invalide
                resp_invalid = await client.post(login_url, data={"username": invalid_username, "password": "wrong_password"})
                msg_invalid = resp_invalid.text

                enumeration_possible = msg_valid != msg_invalid

                return {
                    "vulnerability_confirmed": enumeration_possible,
                    "valid_user_response": msg_valid[:100],
                    "invalid_user_response": msg_invalid[:100],
                    "summary": "Messages d'erreur différents : Énumération possible." if enumeration_possible else "Messages identiques : Protection OK."
                }
        except Exception as e:
            return {
                "vulnerability_confirmed": False,
                "error": f"Erreur de connexion : {str(e)}",
                "summary": f"Impossible d'effectuer le test : {str(e)}"
            }
