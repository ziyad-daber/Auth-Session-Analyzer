"""
backend/masvs/acceptance_criteria.py
Générateur de critères d'acceptation de sécurité pour user stories
"""

from datetime import datetime
from typing import Dict, List, Any, Optional


class AcceptanceCriteriaGenerator:
    """
    Génère des critères d'acceptation de sécurité basés sur:
    - Les vulnérabilités détectées
    - Le type d'authentification
    - Les exigences MASVS applicables
    - Le contexte de la user story
    """

    # Critères génériques par type d'authentification
    AUTH_TYPE_CRITERIA = {
        "jwt": [
            {
                "id": "JWT-AC-01",
                "title": "Token Expiration",
                "criterion": "Les access tokens doivent expirer après une durée maximale de 24 heures",
                "verification": "Analyse statique du claim 'exp' dans les JWT",
                "priority": "HIGH",
                "masvs_ref": "V4.5-3"
            },
            {
                "id": "JWT-AC-02",
                "title": "Secure Token Storage",
                "criterion": "Les tokens doivent être stockés dans EncryptedSharedPreferences ou Android Keystore",
                "verification": "Revue de code + analyse statique des patterns de stockage",
                "priority": "HIGH",
                "masvs_ref": "V7.1-1"
            },
            {
                "id": "JWT-AC-03",
                "title": "Token Rotation",
                "criterion": "Les refresh tokens doivent être à usage unique avec rotation",
                "verification": "Test dynamique de réutilisation de refresh token",
                "priority": "HIGH",
                "masvs_ref": "V4.5-4"
            },
            {
                "id": "JWT-AC-04",
                "title": "Signature Algorithm",
                "criterion": "Les tokens doivent utiliser un algorithme de signature fort (RS256, ES256, ou HS256 avec secret fort)",
                "verification": "Analyse du header JWT et configuration serveur",
                "priority": "MEDIUM",
                "masvs_ref": "V4.5-1"
            },
            {
                "id": "JWT-AC-05",
                "title": "Required Claims",
                "criterion": "Les tokens doivent inclure les claims: exp, iat, iss, sub, aud",
                "verification": "Analyse statique des claims JWT",
                "priority": "MEDIUM",
                "masvs_ref": "V4.5-1"
            }
        ],
        "session": [
            {
                "id": "SESSION-AC-01",
                "title": "Session Regeneration",
                "criterion": "Le session ID doit être régénéré immédiatement après authentification réussie",
                "verification": "Test dynamique de fixation de session",
                "priority": "CRITICAL",
                "masvs_ref": "V6.4-1"
            },
            {
                "id": "SESSION-AC-02",
                "title": "Logout Invalidation",
                "criterion": "Le logout doit invalider la session côté serveur et rejeter les requêtes ultérieures",
                "verification": "Test de replay de token après logout",
                "priority": "HIGH",
                "masvs_ref": "V6.3-1"
            },
            {
                "id": "SESSION-AC-03",
                "title": "Absolute Timeout",
                "criterion": "Les sessions doivent expirer après un timeout absolu de 8-24 heures maximum",
                "verification": "Test dynamique de timeout absolu",
                "priority": "HIGH",
                "masvs_ref": "V6.2-1"
            },
            {
                "id": "SESSION-AC-04",
                "title": "Idle Timeout",
                "criterion": "Les sessions doivent expirer après 15-30 minutes d'inactivité",
                "verification": "Test dynamique de timeout idle",
                "priority": "MEDIUM",
                "masvs_ref": "V6.2-2"
            },
            {
                "id": "SESSION-AC-05",
                "title": "Session ID Quality",
                "criterion": "Les session IDs doivent avoir une entropie suffisante (>64 bits)",
                "verification": "Analyse statistique de l'entropie des session IDs",
                "priority": "HIGH",
                "masvs_ref": "V6.1-1"
            }
        ],
        "oauth2": [
            {
                "id": "OAUTH2-AC-01",
                "title": "PKCE Implementation",
                "criterion": "PKCE (Proof Key for Code Exchange) doit être implémenté pour les clients publics",
                "verification": "Analyse des flux OAuth2 avec code_verifier/code_challenge",
                "priority": "CRITICAL",
                "masvs_ref": "V4.5-2"
            },
            {
                "id": "OAUTH2-AC-02",
                "title": "Redirect URI Validation",
                "criterion": "Les redirect URIs doivent être validés strictement (whitelist)",
                "verification": "Test d'injection de redirect URI",
                "priority": "HIGH",
                "masvs_ref": "V4.5-2"
            },
            {
                "id": "OAUTH2-AC-03",
                "title": "State Parameter",
                "criterion": "Le paramètre state doit être utilisé pour prévenir les attaques CSRF",
                "verification": "Analyse des requêtes d'autorisation OAuth2",
                "priority": "HIGH",
                "masvs_ref": "V4.4-1"
            },
            {
                "id": "OAUTH2-AC-04",
                "title": "Scope Validation",
                "criterion": "Les scopes demandés doivent être validés et limités au minimum nécessaire",
                "verification": "Revue des permissions OAuth2 demandées",
                "priority": "MEDIUM",
                "masvs_ref": "V4.5-1"
            }
        ],
        "basic_auth": [
            {
                "id": "BASIC-AC-01",
                "title": "HTTPS Only",
                "criterion": "Basic Auth ne doit être utilisé que sur HTTPS avec HSTS activé",
                "verification": "Analyse de configuration TLS et headers HSTS",
                "priority": "CRITICAL",
                "masvs_ref": "V12.1-1"
            },
            {
                "id": "BASIC-AC-02",
                "title": "Rate Limiting",
                "criterion": "Rate limiting doit être implémenté pour prévenir le bruteforce",
                "verification": "Test de rate limiting sur endpoint d'authentification",
                "priority": "HIGH",
                "masvs_ref": "V4.1-3"
            }
        ],
        "api_key": [
            {
                "id": "APIKEY-AC-01",
                "title": "Secure Storage",
                "criterion": "Les API keys ne doivent pas être hardcodées dans le code source",
                "verification": "Analyse statique de secret scanning",
                "priority": "CRITICAL",
                "masvs_ref": "V7.1-1"
            },
            {
                "id": "APIKEY-AC-02",
                "title": "Key Rotation",
                "criterion": "Un mécanisme de rotation des API keys doit être disponible",
                "verification": "Revue de l'API de gestion des clés",
                "priority": "MEDIUM",
                "masvs_ref": "V4.5-4"
            }
        ]
    }

    # Critères génériques applicables à tous les types
    GENERIC_CRITERIA = [
        {
            "id": "GENERIC-AC-01",
            "title": "Secure Communication",
            "criterion": "Toutes les communications d'authentification doivent utiliser HTTPS avec validation de certificat",
            "verification": "Analyse de configuration TLS et tests de pinning",
            "priority": "CRITICAL",
            "masvs_ref": "V12.1-1, V12.2-1"
        },
        {
            "id": "GENERIC-AC-02",
            "title": "Account Lockout",
            "criterion": "Un lockout de compte doit se produire après 5-10 tentatives de connexion échouées",
            "verification": "Test dynamique de bruteforce avec seuil de lockout",
            "priority": "HIGH",
            "masvs_ref": "V4.1-3"
        },
        {
            "id": "GENERIC-AC-03",
            "title": "Username Enumeration Prevention",
            "criterion": "Les messages d'erreur de connexion ne doivent pas révéler si un username existe",
            "verification": "Test d'énumération avec usernames valides/invalides",
            "priority": "HIGH",
            "masvs_ref": "V4.2-1"
        },
        {
            "id": "GENERIC-AC-04",
            "title": "No Sensitive Data in Logs",
            "criterion": "Les tokens, mots de passe et secrets ne doivent jamais être loggés dans Logcat",
            "verification": "Analyse statique des appels Log + analyse dynamique du trafic Logcat",
            "priority": "HIGH",
            "masvs_ref": "V7.3-1"
        },
        {
            "id": "GENERIC-AC-05",
            "title": "No Credentials in URL",
            "criterion": "Les credentials et tokens ne doivent jamais apparaître dans les URLs",
            "verification": "Analyse statique et dynamique des URLs",
            "priority": "HIGH",
            "masvs_ref": "V7.3-2"
        }
    ]

    # Critères liés aux vulnérabilités courantes
    VULNERABILITY_CRITERIA = {
        "JWT_TOKEN_LEAK": {
            "id": "VULN-JWT-01",
            "title": "Prevent JWT Token Leak",
            "criterion": "Les tokens JWT ne doivent pas être exposés dans les logs, URLs, ou stockage non sécurisé",
            "verification": "Analyse de fuite de tokens + tests de leakage",
            "priority": "CRITICAL",
            "masvs_ref": "V7.3-1, V7.3-2"
        },
        "HARDCODED_SECRET": {
            "id": "VULN-SECRET-01",
            "title": "No Hardcoded Secrets",
            "criterion": "Aucun secret, clé API, ou mot de passe ne doit être hardcodé dans le code",
            "verification": "Secret scanning statique + revue de code",
            "priority": "CRITICAL",
            "masvs_ref": "V7.1-1"
        },
        "WEAK_CRYPTO": {
            "id": "VULN-CRYPTO-01",
            "title": "Strong Cryptography",
            "criterion": "Utiliser uniquement des algorithmes cryptographiques forts (AES-GCM, ChaCha20, SHA-256+)",
            "verification": "Analyse statique des appels cryptographiques",
            "priority": "HIGH",
            "masvs_ref": "V7.2-1"
        },
        "INSECURE_HTTP": {
            "id": "VULN-NET-01",
            "title": "HTTPS Only",
            "criterion": "Tous les endpoints doivent utiliser HTTPS, aucun HTTP en clair",
            "verification": "Analyse statique des URLs + test dynamique",
            "priority": "CRITICAL",
            "masvs_ref": "V12.1-1"
        },
        "SESSION_FIXATION": {
            "id": "VULN-SESSION-01",
            "title": "Session Fixation Prevention",
            "criterion": "Le session ID doit changer après authentification et tout changement de privilèges",
            "verification": "Test dynamique de fixation de session",
            "priority": "CRITICAL",
            "masvs_ref": "V6.4-1"
        },
        "MISSING_EXP_CLAIM": {
            "id": "VULN-JWT-02",
            "title": "Token Expiration Required",
            "criterion": "Tous les tokens JWT doivent inclure un claim 'exp' avec expiration raisonnable",
            "verification": "Analyse statique des claims JWT",
            "priority": "HIGH",
            "masvs_ref": "V4.5-3"
        },
        "TOKEN_REPLAY": {
            "id": "VULN-TOKEN-01",
            "title": "Token Revocation",
            "criterion": "Les tokens doivent être invalidés côté serveur après logout",
            "verification": "Test de replay après logout",
            "priority": "HIGH",
            "masvs_ref": "V6.3-1"
        }
    }

    def __init__(self):
        self.generated_criteria = []

    def generate(
        self,
        auth_type: str = None,
        vulnerabilities: List[Dict] = None,
        user_story: str = None,
        app_context: Dict = None
    ) -> List[Dict[str, Any]]:
        """
        Génère une liste complète de critères d'acceptation.

        Args:
            auth_type: Type d'authentification (jwt, oauth2, session, etc.)
            vulnerabilities: Liste des vulnérabilités détectées
            user_story: Description de la user story
            app_context: Contexte applicatif (optionnel)

        Returns:
            Liste de critères d'acceptation structurés
        """
        self.generated_criteria = []

        # 1. Ajouter les critères génériques (toujours applicables)
        for criteria in self.GENERIC_CRITERIA:
            self.generated_criteria.append(criteria)

        # 2. Ajouter les critères spécifiques au type d'auth
        if auth_type:
            auth_types = [auth_type] if isinstance(auth_type, str) else auth_type
            for at in auth_types:
                if at in self.AUTH_TYPE_CRITERIA:
                    for criteria in self.AUTH_TYPE_CRITERIA[at]:
                        if not self._criterion_exists(criteria["id"]):
                            self.generated_criteria.append(criteria)

        # 3. Ajouter les critères basés sur les vulnérabilités détectées
        if vulnerabilities:
            for vuln in vulnerabilities:
                vuln_type = vuln.get("type", "").upper()
                if vuln_type in self.VULNERABILITY_CRITERIA:
                    criteria = self.VULNERABILITY_CRITERIA[vuln_type].copy()
                    criteria["triggered_by"] = vuln_type
                    criteria["severity"] = vuln.get("severity", "UNKNOWN")
                    if not self._criterion_exists(criteria["id"]):
                        self.generated_criteria.append(criteria)

        # 4. Ajouter des critères contextuels si user story fournie
        if user_story:
            context_criteria = self._generate_context_criteria(user_story)
            for criteria in context_criteria:
                if not self._criterion_exists(criteria["id"]):
                    self.generated_criteria.append(criteria)

        # 5. Prioriser et ordonner
        self.generated_criteria = self._prioritize_criteria(self.generated_criteria)

        return self.generated_criteria

    def _criterion_exists(self, criterion_id: str) -> bool:
        """Vérifie si un critère existe déjà dans la liste."""
        return any(c.get("id") == criterion_id for c in self.generated_criteria)

    def _generate_context_criteria(self, user_story: str) -> List[Dict]:
        """Génère des critères basés sur le contexte de la user story."""
        criteria = []
        story_lower = user_story.lower()

        # Détection de contexte
        if "password" in story_lower or "mot de passe" in story_lower:
            criteria.append({
                "id": "CTX-PWD-01",
                "title": "Password Policy",
                "criterion": "Les mots de passe doivent respecter une politique de complexité (min 8 chars, maj/min/chiffre/caractère spécial)",
                "verification": "Test de validation de mot de passe faible/fort",
                "priority": "HIGH",
                "masvs_ref": "V4.1-1"
            })

        if "biometric" in story_lower or "biométrique" in story_lower:
            criteria.append({
                "id": "CTX-BIO-01",
                "title": "Biometric Authentication",
                "criterion": "L'authentification biométrique doit utiliser Android BiometricPrompt avec CryptoObject",
                "verification": "Revue de code + test dynamique biométrique",
                "priority": "HIGH",
                "masvs_ref": "V4.1-2"
            })

        if "remember" in story_lower or "souvenir" in story_lower or "persist" in story_lower:
            criteria.append({
                "id": "CTX-PERSIST-01",
                "title": "Persistent Session Security",
                "criterion": "Les sessions persistantes doivent utiliser des refresh tokens sécurisés avec rotation",
                "verification": "Analyse de stockage + test de rotation",
                "priority": "HIGH",
                "masvs_ref": "V4.5-4"
            })

        if "logout" in story_lower or "déconnexion" in story_lower:
            criteria.append({
                "id": "CTX-LOGOUT-01",
                "title": "Complete Logout",
                "criterion": "Le logout doit invalider tous les tokens (access + refresh) côté serveur",
                "verification": "Test de replay de tous les tokens après logout",
                "priority": "HIGH",
                "masvs_ref": "V6.3-1"
            })

        if "multi-device" in story_lower or "multi-appareil" in story_lower or "concurrent" in story_lower:
            criteria.append({
                "id": "CTX-MULTI-01",
                "title": "Multi-Device Session Management",
                "criterion": "Les sessions concurrentes doivent être trackées et révocables individuellement",
                "verification": "Test de sessions multiples + révocation sélective",
                "priority": "MEDIUM",
                "masvs_ref": "V6.3-2"
            })

        return criteria

    def _prioritize_criteria(self, criteria: List[Dict]) -> List[Dict]:
        """Ordonne les critères par priorité (CRITICAL > HIGH > MEDIUM > LOW)."""
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(
            criteria,
            key=lambda c: priority_order.get(c.get("priority", "LOW"), 4)
        )

    def export_markdown(self, criteria: List[Dict] = None) -> str:
        """Exporte les critères d'acceptation en format Markdown."""
        if criteria is None:
            criteria = self.generated_criteria

        md = []
        md.append("# Critères d'Acceptation de Sécurité")
        md.append("")
        md.append(f"**Généré le:** {datetime.now().isoformat()}")
        md.append(f"**Total critères:** {len(criteria)}")
        md.append("")

        # Résumé par priorité
        priority_counts = {}
        for c in criteria:
            p = c.get("priority", "UNKNOWN")
            priority_counts[p] = priority_counts.get(p, 0) + 1

        md.append("## 📊 Résumé par Priorité")
        md.append("")
        for priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = priority_counts.get(priority, 0)
            if count > 0:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(priority, "⚪")
                md.append(f"- {icon} **{priority}:** {count}")
        md.append("")

        # Liste détaillée
        md.append("## 📋 Critères Détaillés")
        md.append("")

        for i, c in enumerate(criteria, 1):
            priority_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(c.get("priority", ""), "⚪")
            md.append(f"### {i}. {priority_icon} [{c.get('id')}] {c.get('title')}")
            md.append("")
            md.append(f"**Critère:** {c.get('criterion')}")
            md.append("")
            md.append(f"**Vérification:** {c.get('verification')}")
            md.append("")
            if c.get("masvs_ref"):
                md.append(f"**Référence MASVS:** {c.get('masvs_ref')}")
                md.append("")
            if c.get("triggered_by"):
                md.append(f"**Déclenché par:** {c.get('triggered_by')}")
                md.append("")

        return "\n".join(md)

    def export_json(self, criteria: List[Dict] = None, pretty: bool = True) -> str:
        """Exporte les critères d'acceptation en format JSON."""
        import json
        if criteria is None:
            criteria = self.generated_criteria

        output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_criteria": len(criteria)
            },
            "criteria": criteria
        }

        if pretty:
            return json.dumps(output, indent=2, ensure_ascii=False)
        return json.dumps(output, ensure_ascii=False)

    def filter_by_priority(self, criteria: List[Dict], min_priority: str) -> List[Dict]:
        """Filtre les critères par priorité minimale."""
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        min_level = priority_order.get(min_priority, 4)
        return [c for c in criteria if priority_order.get(c.get("priority", "LOW"), 4) <= min_level]

    def filter_by_masvs_chapter(self, criteria: List[Dict], chapter: int) -> List[Dict]:
        """Filtre les critères par chapitre MASVS."""
        filtered = []
        for c in criteria:
            masvs_ref = c.get("masvs_ref", "")
            if masvs_ref:
                # Extraire le numéro de chapitre (ex: V4.1-3 -> Chapitre 4)
                import re
                match = re.search(r'V(\d+)', masvs_ref)
                if match and int(match.group(1)) == chapter:
                    filtered.append(c)
        return filtered
