"""
backend/masvs/masvs_database.py
Base de données des exigences MASVS v2.0 pour l'authentification et la gestion de session
"""

from typing import Dict, List, Any


# MASVS - Mobile Application Security Verification Standard
# Référence: https://owasp.org/www-project-mobile-app-security/

MASVS_AUTH_AND_SESSION = {
    # =========================================================================
    # CHAPTER 4 - AUTHENTICATION
    # =========================================================================
    "V4.1": {
        "title": "Password Policy",
        "description": "L'application doit exiger des mots de passe forts et limiter les tentatives de connexion.",
        "lab": "Lab 4.1 - Testing Password Policy",
        "checks": [
            {
                "id": "V4.1-1",
                "name": "Minimum password length",
                "description": "Le mot de passe doit avoir au moins 8 caractères",
                "test_method": "static",
                "auth_types": ["password", "session"]
            },
            {
                "id": "V4.1-2",
                "name": "Password complexity",
                "description": "L'application exige des caractères spéciaux, chiffres, majuscules",
                "test_method": "static",
                "auth_types": ["password", "session"]
            },
            {
                "id": "V4.1-3",
                "name": "Account lockout policy",
                "description": "Le compte est verrouillé après 5-10 tentatives échouées",
                "test_method": "dynamic",
                "auth_types": ["password", "session", "jwt"]
            },
            {
                "id": "V4.1-4",
                "name": "Progressive delay",
                "description": "Délai progressif entre les tentatives de connexion",
                "test_method": "dynamic",
                "auth_types": ["password", "session", "jwt"]
            }
        ]
    },
    "V4.2": {
        "title": "Username Enumeration",
        "description": "L'application ne doit pas révéler l'existence des noms d'utilisateurs.",
        "lab": "Lab 4.2 - Testing Username Enumeration",
        "checks": [
            {
                "id": "V4.2-1",
                "name": "Generic error messages",
                "description": "Les messages d'erreur ne révèlent pas si l'utilisateur existe",
                "test_method": "dynamic",
                "auth_types": ["password", "session", "jwt"]
            },
            {
                "id": "V4.2-2",
                "name": "Consistent response timing",
                "description": "Le temps de réponse est similaire pour utilisateur existant/inexistant",
                "test_method": "dynamic",
                "auth_types": ["password", "session", "jwt"]
            }
        ]
    },
    "V4.3": {
        "title": "Credential Recovery",
        "description": "Les mécanismes de récupération de mots de passe doivent être sécurisés.",
        "lab": "Lab 4.3 - Testing Credential Recovery",
        "checks": [
            {
                "id": "V4.3-1",
                "name": "Secure password reset",
                "description": "Token de réinitialisation à usage unique et à expiration courte",
                "test_method": "static",
                "auth_types": ["password", "session"]
            },
            {
                "id": "V4.3-2",
                "name": "No security questions",
                "description": "Pas de questions de sécurité à réponses prévisibles",
                "test_method": "static",
                "auth_types": ["password", "session"]
            }
        ]
    },
    "V4.4": {
        "title": "Session Management",
        "description": "La gestion des sessions doit suivre les bonnes pratiques de sécurité.",
        "lab": "Lab 4.4 - Testing Session Management",
        "checks": [
            {
                "id": "V4.4-1",
                "name": "Session ID regeneration",
                "description": "Nouveau session ID généré après authentification réussie",
                "test_method": "dynamic",
                "auth_types": ["session"]
            },
            {
                "id": "V4.4-2",
                "name": "Session fixation protection",
                "description": "L'application est protégée contre la fixation de session",
                "test_method": "dynamic",
                "auth_types": ["session"]
            },
            {
                "id": "V4.4-3",
                "name": "Session timeout",
                "description": "Les sessions expirent après une période d'inactivité",
                "test_method": "dynamic",
                "auth_types": ["session", "jwt"]
            }
        ]
    },
    "V4.5": {
        "title": "Token Security",
        "description": "Les tokens d'authentification doivent être stockés et transmis de manière sécurisée.",
        "lab": "Lab 4.5 - Testing Token Security",
        "checks": [
            {
                "id": "V4.5-1",
                "name": "Secure token storage",
                "description": "Les tokens ne sont pas stockés en clair dans SharedPreferences",
                "test_method": "static",
                "auth_types": ["jwt", "oauth2"]
            },
            {
                "id": "V4.5-2",
                "name": "Token transmission over HTTPS",
                "description": "Les tokens sont toujours transmis sur HTTPS",
                "test_method": "dynamic",
                "auth_types": ["jwt", "oauth2", "session"]
            },
            {
                "id": "V4.5-3",
                "name": "Token expiration",
                "description": "Les tokens ont une durée de vie limitée",
                "test_method": "static",
                "auth_types": ["jwt", "oauth2"]
            },
            {
                "id": "V4.5-4",
                "name": "Refresh token rotation",
                "description": "Les refresh tokens sont renouvelés à chaque usage",
                "test_method": "dynamic",
                "auth_types": ["jwt", "oauth2"]
            }
        ]
    },

    # =========================================================================
    # CHAPTER 6 - SESSION MANAGEMENT (Detailed)
    # =========================================================================
    "V6.1": {
        "title": "Session ID Quality",
        "description": "Les identifiants de session doivent avoir une entropie suffisante.",
        "lab": "Lab 6.1 - Testing Session ID Quality",
        "checks": [
            {
                "id": "V6.1-1",
                "name": "Session ID entropy",
                "description": "Le session ID a au moins 64 bits d'entropie",
                "test_method": "static",
                "auth_types": ["session"]
            },
            {
                "id": "V6.1-2",
                "name": "Random session ID generation",
                "description": "Les session IDs sont générés de manière imprévisible",
                "test_method": "static",
                "auth_types": ["session"]
            }
        ]
    },
    "V6.2": {
        "title": "Session Expiration",
        "description": "Les sessions doivent expirer correctement.",
        "lab": "Lab 6.2 - Testing Session Expiration",
        "checks": [
            {
                "id": "V6.2-1",
                "name": "Absolute timeout",
                "description": "La session expire après une durée maximale absolue",
                "test_method": "dynamic",
                "auth_types": ["session", "jwt"]
            },
            {
                "id": "V6.2-2",
                "name": "Idle timeout",
                "description": "La session expire après une période d'inactivité",
                "test_method": "dynamic",
                "auth_types": ["session", "jwt"]
            },
            {
                "id": "V6.2-3",
                "name": "Server-side expiration",
                "description": "L'expiration est gérée côté serveur, pas seulement client",
                "test_method": "dynamic",
                "auth_types": ["session", "jwt"]
            }
        ]
    },
    "V6.3": {
        "title": "Session Invalidation",
        "description": "Les sessions doivent être correctement invalidées.",
        "lab": "Lab 6.3 - Testing Session Invalidation",
        "checks": [
            {
                "id": "V6.3-1",
                "name": "Logout invalidation",
                "description": "Le logout invalide la session côté serveur",
                "test_method": "dynamic",
                "auth_types": ["session", "jwt"]
            },
            {
                "id": "V6.3-2",
                "name": "Token replay prevention",
                "description": "Un token utilisé après logout est rejeté",
                "test_method": "dynamic",
                "auth_types": ["jwt", "session"]
            },
            {
                "id": "V6.3-3",
                "name": "Password change invalidation",
                "description": "Changer le mot de passe invalide toutes les sessions",
                "test_method": "dynamic",
                "auth_types": ["session", "jwt"]
            }
        ]
    },
    "V6.4": {
        "title": "Session Fixation",
        "description": "L'application doit être protégée contre la fixation de session.",
        "lab": "Lab 6.4 - Testing Session Fixation",
        "checks": [
            {
                "id": "V6.4-1",
                "name": "Session ID regeneration on login",
                "description": "Le session ID change après authentification",
                "test_method": "dynamic",
                "auth_types": ["session"]
            },
            {
                "id": "V6.4-2",
                "name": "No session ID in URL",
                "description": "Le session ID n'est jamais passé dans l'URL",
                "test_method": "static",
                "auth_types": ["session"]
            },
            {
                "id": "V6.4-3",
                "name": "Reject known session IDs",
                "description": "Les session IDs pré-authentification sont rejetés post-authentification",
                "test_method": "dynamic",
                "auth_types": ["session"]
            }
        ]
    },

    # =========================================================================
    # CHAPTER 7 - DATA STORAGE (Relevant to Auth)
    # =========================================================================
    "V7.1": {
        "title": "Secure Storage",
        "description": "Les données sensibles doivent être stockées de manière sécurisée.",
        "lab": "Lab 7.1 - Testing Local Storage",
        "checks": [
            {
                "id": "V7.1-1",
                "name": "No hardcoded credentials",
                "description": "Aucun mot de passe ou secret n'est codé en dur",
                "test_method": "static",
                "auth_types": ["all"]
            },
            {
                "id": "V7.1-2",
                "name": "No tokens in SharedPreferences",
                "description": "Les tokens ne sont pas stockés dans SharedPreferences en clair",
                "test_method": "static",
                "auth_types": ["jwt", "session"]
            },
            {
                "id": "V7.1-3",
                "name": "Encrypted sensitive data",
                "description": "Les données sensibles sont chiffrées au repos",
                "test_method": "static",
                "auth_types": ["all"]
            }
        ]
    },
    "V7.2": {
        "title": "Cryptographic Usage",
        "description": "L'application doit utiliser des algorithmes cryptographiques sécurisés.",
        "lab": "Lab 7.2 - Testing Cryptographic Algorithms",
        "checks": [
            {
                "id": "V7.2-1",
                "name": "No weak crypto algorithms",
                "description": "Pas d'algorithmes faibles (DES, RC4, MD5, SHA1)",
                "test_method": "static",
                "auth_types": ["all"]
            },
            {
                "id": "V7.2-2",
                "name": "Secure random generation",
                "description": "Utilisation de SecureRandom pour les secrets et tokens",
                "test_method": "static",
                "auth_types": ["session", "jwt"]
            }
        ]
    },
    "V7.3": {
        "title": "Sensitive Data Protection",
        "description": "Les données sensibles ne doivent pas fuiter.",
        "lab": "Lab 7.3 - Testing Sensitive Data",
        "checks": [
            {
                "id": "V7.3-1",
                "name": "No credentials in logs",
                "description": "Les mots de passe et tokens ne sont pas logués",
                "test_method": "static",
                "auth_types": ["all"]
            },
            {
                "id": "V7.3-2",
                "name": "No tokens in URLs",
                "description": "Les tokens ne sont pas passés dans les URLs",
                "test_method": "dynamic",
                "auth_types": ["jwt", "session"]
            }
        ]
    },

    # =========================================================================
    # CHAPTER 12 - NETWORK COMMUNICATIONS
    # =========================================================================
    "V12.1": {
        "title": "HTTPS Enforcement",
        "description": "Toutes les communications doivent utiliser HTTPS.",
        "lab": "Lab 12.1 - Testing HTTPS",
        "checks": [
            {
                "id": "V12.1-1",
                "name": "No HTTP endpoints",
                "description": "Aucune connexion HTTP non sécurisée",
                "test_method": "static",
                "auth_types": ["all"]
            },
            {
                "id": "V12.1-2",
                "name": "HSTS enabled",
                "description": "HSTS est activé pour forcer HTTPS",
                "test_method": "dynamic",
                "auth_types": ["all"]
            }
        ]
    },
    "V12.2": {
        "title": "Certificate Validation",
        "description": "Les certificats SSL/TLS doivent être validés correctement.",
        "lab": "Lab 12.2 - Testing Certificate Validation",
        "checks": [
            {
                "id": "V12.2-1",
                "name": "Certificate chain validation",
                "description": "La chaîne de certificats est validée",
                "test_method": "dynamic",
                "auth_types": ["all"]
            },
            {
                "id": "V12.2-2",
                "name": "No custom TrustManager",
                "description": "Pas de TrustManager personnalisé qui accepte tous les certificats",
                "test_method": "static",
                "auth_types": ["all"]
            }
        ]
    },
    "V12.3": {
        "title": "SSL Pinning",
        "description": "Le certificat du serveur doit être épinglé.",
        "lab": "Lab 12.3 - Testing SSL Pinning",
        "checks": [
            {
                "id": "V12.3-1",
                "name": "Certificate pinning implemented",
                "description": "Le certificat ou la clé publique est épinglé",
                "test_method": "static",
                "auth_types": ["all"]
            },
            {
                "id": "V12.3-2",
                "name": "Pinning enforced",
                "description": "Le pinning ne peut pas être bypassé facilement",
                "test_method": "dynamic",
                "auth_types": ["all"]
            }
        ]
    },

    # =========================================================================
    # CHAPTER 14 - RESILIENCE (Relevant to Auth)
    # =========================================================================
    "V14.1": {
        "title": "Tamper Detection",
        "description": "L'application doit détecter les modifications.",
        "lab": "Lab 14.1 - Testing Tamper Detection",
        "checks": [
            {
                "id": "V14.1-1",
                "name": "Integrity checks",
                "description": "L'application vérifie son intégrité au démarrage",
                "test_method": "static",
                "auth_types": ["all"]
            },
            {
                "id": "V14.1-2",
                "name": "Response to tampering",
                "description": "L'application refuse de fonctionner si modifiée",
                "test_method": "dynamic",
                "auth_types": ["all"]
            }
        ]
    },
    "V14.2": {
        "title": "Root Detection",
        "description": "L'application doit détecter les appareils rootés.",
        "lab": "Lab 14.2 - Testing Root Detection",
        "checks": [
            {
                "id": "V14.2-1",
                "name": "Root detection implemented",
                "description": "L'application détecte le root/jailbreak",
                "test_method": "dynamic",
                "auth_types": ["all"]
            },
            {
                "id": "V14.2-2",
                "name": "Response to root",
                "description": "Fonctionnalités limitées ou bloquées sur appareil rooté",
                "test_method": "dynamic",
                "auth_types": ["all"]
            }
        ]
    }
}


# Mapping des types d'authentification vers les exigences applicables
AUTH_TYPE_REQUIREMENTS = {
    "jwt": ["V4.1", "V4.2", "V4.5", "V6.2", "V6.3", "V7.1", "V7.2", "V7.3", "V12.1", "V12.2", "V12.3"],
    "oauth2": ["V4.1", "V4.2", "V4.5", "V6.2", "V6.3", "V7.1", "V12.1", "V12.2", "V12.3"],
    "session": ["V4.1", "V4.2", "V4.4", "V6.1", "V6.2", "V6.3", "V6.4", "V7.1", "V7.2", "V7.3", "V12.1"],
    "password": ["V4.1", "V4.2", "V4.3", "V7.1", "V12.1"],
    "all": list(MASVS_AUTH_AND_SESSION.keys())
}


def get_masvs_database() -> Dict[str, Any]:
    """Retourne la base de données complète MASVS."""
    return MASVS_AUTH_AND_SESSION


def get_requirements_for_auth_type(auth_type: str) -> List[str]:
    """Retourne les IDs des exigences applicables à un type d'auth."""
    return AUTH_TYPE_REQUIREMENTS.get(auth_type, AUTH_TYPE_REQUIREMENTS["all"])


def get_requirement_details(requirement_id: str) -> Dict[str, Any]:
    """Retourne les détails d'une exigence spécifique."""
    return MASVS_AUTH_AND_SESSION.get(requirement_id, {})


def get_check_details(requirement_id: str, check_id: str) -> Dict[str, Any]:
    """Retourne les détails d'un check spécifique."""
    requirement = MASVS_AUTH_AND_SESSION.get(requirement_id, {})
    checks = requirement.get("checks", [])
    for check in checks:
        if check.get("id") == check_id:
            return check
    return {}
