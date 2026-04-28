"""
backend/correlation_engine/token_analyzer.py
Analyse d'entropie et cassage de secrets JWT
"""

import math
import jwt
import os
from collections import Counter

class TokenAnalyzer:
    def __init__(self, wordlist_path=None):
        self.wordlist_path = wordlist_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            "tools", "wordlists", "jwt_secrets.txt"
        )

    def calculate_entropy(self, text: str) -> float:
        """Calcule l'entropie de Shannon d'une chaîne de caractères."""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((c/length) * math.log2(c/length) for c in counts.values())

    def crack_jwt_secret(self, token: str) -> dict:
        """Tente de cracker le secret HMAC d'un JWT via une wordlist."""
        try:
            # On récupère le header pour connaître l'algorithme
            header = jwt.get_unverified_header(token)
            alg = header.get("alg", "HS256")
            
            if not alg.startswith("HS"):
                return {"cracked": False, "message": f"Algorithme {alg} non supporté pour le crackage symétrique."}

            if not os.path.exists(self.wordlist_path):
                return {"cracked": False, "message": "Wordlist manquante."}

            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    secret = line.strip()
                    if not secret: continue
                    try:
                        jwt.decode(token, secret, algorithms=[alg])
                        # Si on arrive ici, le secret est valide !
                        return {
                            "cracked": True,
                            "secret": secret,
                            "entropy": round(self.calculate_entropy(secret), 2),
                            "message": f"Secret cracké : {secret}"
                        }
                    except (jwt.InvalidSignatureError, jwt.DecodeError):
                        continue
            
            return {"cracked": False, "message": "Secret non trouvé dans la wordlist."}
            
        except Exception as e:
            return {"cracked": False, "message": f"Erreur : {str(e)}"}

    def get_token_info(self, token: str) -> dict:
        """Analyse complète d'un token."""
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            return {
                "header": header,
                "payload": payload,
                "entropy": round(self.calculate_entropy(token), 2)
            }
        except:
            return {"error": "Invalid token"}
