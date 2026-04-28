"""
correlation_engine/cvss_scorer.py
───────────────────────────────────
Calcul automatique des scores CVSS v3.1 pour chaque finding.
Fournit également un score de risque global de l'application.
"""

from typing import Dict, Any, List


# ─── Vecteurs CVSS v3.1 ──────────────────────────────────────────────────────
# Format : (AV, AC, PR, UI, S, C, I, A) → score de base approximatif
#
# Chaque vulnérabilité a un vecteur CVSS prédéfini.

CVSS_VECTORS: Dict[str, Dict[str, Any]] = {
    "JWT_ALG_NONE": {
        "vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score":  9.1,
        "severity":    "CRITICAL",
        "description": "JWT algorithm confusion — authentication bypass",
    },
    "JWT_WEAK_SECRET": {
        "vector":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score":  8.1,
        "severity":    "HIGH",
        "description": "JWT signed with a weak/guessable secret key",
    },
    "JWT_NO_EXPIRATION": {
        "vector":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "base_score":  6.5,
        "severity":    "HIGH",
        "description": "JWT without expiration — token valid indefinitely",
    },
    "TOKEN_REPLAY_POST_LOGOUT": {
        "vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score":  9.1,
        "severity":    "CRITICAL",
        "description": "Session token valid after logout — server-side session not invalidated",
    },
    "HARDCODED_TOKEN_IN_TRANSIT": {
        "vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score":  9.5,
        "severity":    "CRITICAL",
        "description": "Token hardcoded in source AND observed in network traffic",
    },
    "HARDCODED_PASSWORD": {
        "vector":      "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "base_score":  8.4,
        "severity":    "HIGH",
        "description": "Password hardcoded in source code",
    },
    "NO_BRUTEFORCE_PROTECTION": {
        "vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score":  7.5,
        "severity":    "HIGH",
        "description": "No account lockout or rate limiting on login endpoint",
    },
    "UNENCRYPTED_HTTP": {
        "vector":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "base_score":  7.4,
        "severity":    "HIGH",
        "description": "Authentication credentials transmitted over HTTP (unencrypted)",
    },
    "USERNAME_ENUMERATION": {
        "vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "base_score":  5.3,
        "severity":    "MEDIUM",
        "description": "Username enumeration possible via different error messages",
    },
    "SESSION_FIXATION": {
        "vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "base_score":  8.0,
        "severity":    "HIGH",
        "description": "Session ID not regenerated after login — session fixation possible",
    },
    "INSECURE_COOKIE": {
        "vector":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score":  5.9,
        "severity":    "MEDIUM",
        "description": "Session cookie missing Secure or HttpOnly flag",
    },
}


def get_cvss_for_finding(finding_type: str) -> Dict[str, Any]:
    """
    Retourne le vecteur CVSS pour un type de finding.

    Args:
        finding_type: Clé dans CVSS_VECTORS

    Returns:
        Dict avec vector, base_score, severity, description
        ou valeur par défaut si le type est inconnu
    """
    # TODO: chercher finding_type dans CVSS_VECTORS
    # TODO: si non trouvé, retourner un finding MEDIUM par défaut
    raise NotImplementedError("get_cvss_for_finding — à implémenter")


def elevate_score_if_confirmed(base_score: float, confirmed: bool) -> float:
    """
    Élève le score CVSS de +0.5 si la vulnérabilité est confirmée activement.
    Ne dépasse jamais 10.0.

    Returns:
        Score ajusté
    """
    # TODO: simple calcul min(base_score + 0.5, 10.0) si confirmed
    raise NotImplementedError("elevate_score_if_confirmed — à implémenter")


def compute_risk_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calcule un résumé du risque global à partir d'une liste de findings.

    Returns:
        {
            "total": int,
            "critical": int,
            "high": int,
            "medium": int,
            "low": int,
            "average_cvss": float,
            "max_cvss": float,
        }
    """
    # TODO: compter les findings par severity
    # TODO: calculer la moyenne et le max des scores CVSS
    raise NotImplementedError("compute_risk_summary — à implémenter")
