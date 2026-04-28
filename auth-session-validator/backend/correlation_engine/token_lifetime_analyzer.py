"""
backend/correlation_engine/token_lifetime_analyzer.py
Analyse de la durée de vie des tokens JWT : expiration, rotation, refresh
"""

import jwt
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any


class TokenLifetimeAnalyzer:
    """
    Analyseur de durée de vie et de sécurité des tokens JWT.

    Vérifie :
    - Présence et validité des claims temporels (exp, iat, nbf)
    - Durée de vie excessive (> 24h par défaut)
    - Refresh token security
    - Token rotation detection
    """

    # Seuils de sécurité (en secondes)
    MAX_ACCESS_TOKEN_LIFETIME = 24 * 60 * 60  # 24 heures
    MAX_REFRESH_TOKEN_LIFETIME = 30 * 24 * 60 * 60  # 30 jours
    MIN_TOKEN_LIFETIME = 5 * 60  # 5 minutes (trop court = UX problématique)

    def __init__(self, max_access_lifetime: int = None, max_refresh_lifetime: int = None):
        if max_access_lifetime:
            self.MAX_ACCESS_TOKEN_LIFETIME = max_access_lifetime
        if max_refresh_lifetime:
            self.MAX_REFRESH_TOKEN_LIFETIME = max_refresh_lifetime

    def analyze_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """
        Analyse complète d'un token JWT.

        Args:
            token: Le JWT à analyser
            token_type: "access" ou "refresh"

        Returns:
            Dict avec les résultats de l'analyse
        """
        result = {
            "valid": False,
            "token_type": token_type,
            "claims": {},
            "temporal_claims": {},
            "lifetime_seconds": None,
            "lifetime_human": None,
            "findings": [],
            "recommendations": [],
            "risk_level": "LOW"
        }

        try:
            # Décoder sans vérifier la signature (analyse statique)
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            result["valid"] = True
            result["header"] = header
            result["claims"] = payload

            # Analyser les claims temporels
            temporal = self._extract_temporal_claims(payload)
            result["temporal_claims"] = temporal

            # Calculer la durée de vie
            if temporal.get("exp") and temporal.get("iat"):
                lifetime = temporal["exp"] - temporal["iat"]
                result["lifetime_seconds"] = lifetime
                result["lifetime_human"] = self._format_duration(lifetime)

            # Vérifier la sécurité temporelle
            temporal_findings = self._check_temporal_security(temporal, token_type)
            result["findings"].extend(temporal_findings)

            # Vérifier l'algorithme
            algo_findings = self._check_algorithm(header)
            result["findings"].extend(algo_findings)

            # Vérifier les claims requis
            claims_findings = self._check_required_claims(payload, token_type)
            result["findings"].extend(claims_findings)

            # Calculer le niveau de risque
            result["risk_level"] = self._calculate_risk_level(result["findings"])

            # Générer recommandations
            result["recommendations"] = self._generate_recommendations(result["findings"])

        except jwt.DecodeError as e:
            result["error"] = f"Token invalide: {str(e)}"
            result["findings"].append({
                "type": "INVALID_TOKEN",
                "severity": "HIGH",
                "description": "Le token ne peut pas être décodé"
            })
        except Exception as e:
            result["error"] = f"Erreur d'analyse: {str(e)}"

        return result

    def _extract_temporal_claims(self, payload: Dict) -> Dict[str, Optional[int]]:
        """Extrait et convertit les claims temporels en timestamps lisibles."""
        temporal = {}

        for claim in ["exp", "iat", "nbf"]:
            if claim in payload:
                timestamp = payload[claim]
                if isinstance(timestamp, (int, float)):
                    temporal[claim] = int(timestamp)
                    temporal[f"{claim}_datetime"] = datetime.fromtimestamp(
                        timestamp, tz=timezone.utc
                    ).isoformat()
                else:
                    temporal[claim] = None
            else:
                temporal[claim] = None

        return temporal

    def _check_temporal_security(self, temporal: Dict, token_type: str) -> List[Dict]:
        """Vérifie la sécurité des claims temporels."""
        findings = []
        now = int(datetime.now(timezone.utc).timestamp())

        # Vérifier expiration
        if temporal.get("exp") is None:
            findings.append({
                "type": "MISSING_EXP_CLAIM",
                "severity": "CRITICAL",
                "description": "Le claim 'exp' (expiration) est absent. Le token ne expire jamais.",
                "owasp": "MASVS-AUTH-5",
                "impact": "Un token volé reste valide indéfiniment, permettant un accès permanent."
            })
        elif temporal["exp"] < now:
            findings.append({
                "type": "EXPIRED_TOKEN",
                "severity": "INFO",
                "description": "Le token est expiré depuis le " + temporal.get("exp_datetime", "inconnue"),
                "owasp": "MASVS-AUTH-5"
            })
        else:
            # Vérifier durée de vie excessive
            if temporal.get("iat") and temporal.get("exp"):
                lifetime = temporal["exp"] - temporal["iat"]
                max_lifetime = (
                    self.MAX_REFRESH_TOKEN_LIFETIME if token_type == "refresh"
                    else self.MAX_ACCESS_TOKEN_LIFETIME
                )

                if lifetime > max_lifetime:
                    max_human = self._format_duration(max_lifetime)
                    findings.append({
                        "type": "EXCESSIVE_TOKEN_LIFETIME",
                        "severity": "HIGH" if token_type == "access" else "MEDIUM",
                        "description": f"D durée de vie ({self._format_duration(lifetime)}) dépasse le maximum recommandé ({max_human})",
                        "owasp": "MASVS-AUTH-5",
                        "impact": "Fenêtre d'opportunité étendue pour les attaques par rejeu ou vol de session."
                    })

                # Vérifier durée trop courte (UX)
                if lifetime < self.MIN_TOKEN_LIFETIME:
                    findings.append({
                        "type": "VERY_SHORT_TOKEN_LIFETIME",
                        "severity": "LOW",
                        "description": f"D durée de vie ({self._format_duration(lifetime)}) est très courte, peut causer des problèmes d'UX",
                        "owasp": "MASVS-AUTH-5",
                        "impact": "Rafraîchissements fréquents nécessaires, expérience utilisateur dégradée."
                    })

        # Vérifier iat (issued at)
        if temporal.get("iat") is None:
            findings.append({
                "type": "MISSING_IAT_CLAIM",
                "severity": "MEDIUM",
                "description": "Le claim 'iat' (issued at) est absent. Impossible de connaître l'âge du token.",
                "owasp": "MASVS-AUTH-5",
                "impact": "Difficulté à implémenter la rotation et à détecter les tokens anciens."
            })

        # Vérifier nbf (not before)
        if temporal.get("nbf") is None:
            findings.append({
                "type": "MISSING_NBF_CLAIM",
                "severity": "LOW",
                "description": "Le claim 'nbf' (not before) est absent. Le token est valide immédiatement.",
                "owasp": "MASVS-AUTH-5",
                "impact": "Risque mineur. NBF ajoute une couche de sécurité pour les tokens post-datés."
            })

        # Vérifier cohérence temporelle
        if temporal.get("nbf") and temporal.get("iat"):
            if temporal["nbf"] > temporal["exp"]:
                findings.append({
                    "type": "INVALID_TEMPORAL_ORDER",
                    "severity": "HIGH",
                    "description": "Incohérence: nbf > exp. Le token n'est jamais valide.",
                    "owasp": "MASVS-AUTH-5",
                    "impact": "Token inutilisable - erreur de configuration critique."
                })
            elif temporal["nbf"] > now:
                findings.append({
                    "type": "FUTURE_NBF",
                    "severity": "MEDIUM",
                    "description": "Le token n'est pas encore valide (nbf dans le futur)",
                    "owasp": "MASVS-AUTH-5"
                })

        return findings

    def _check_algorithm(self, header: Dict) -> List[Dict]:
        """Vérifie la sécurité de l'algorithme de signature."""
        findings = []
        alg = header.get("alg", "").upper()

        if not alg or alg == "NONE":
            findings.append({
                "type": "ALG_NONE_VULNERABILITY",
                "severity": "CRITICAL",
                "description": "Algorithme 'none' détecté. Le token n'est pas signé.",
                "owasp": "MASVS-AUTH-1",
                "impact": "N'importe qui peut forger des tokens valides sans connaître de secret."
            })
        elif alg in ["HS256", "HS384", "HS512"]:
            # HMAC - vérifier la force du secret ailleurs
            pass
        elif alg in ["RS256", "RS384", "RS512"]:
            # RSA - OK
            pass
        elif alg in ["ES256", "ES384", "ES512"]:
            # ECDSA - OK
            pass
        else:
            findings.append({
                "type": "UNKNOWN_ALGORITHM",
                "severity": "MEDIUM",
                "description": f"Algorithme inconnu: {alg}",
                "owasp": "MASVS-AUTH-1",
                "impact": "Compatibilité et sécurité incertaines."
            })

        # Vérifier algorithme faible
        if "MD5" in alg.upper() or "SHA1" in alg.upper() or alg == "HS256":
            findings.append({
                "type": "WEAK_SIGNATURE_ALGORITHM",
                "severity": "MEDIUM",
                "description": f"Algorithme de signature potentiellement faible: {alg}",
                "owasp": "MASVS-AUTH-1",
                "impact": "Risque de collision ou de crackage du secret."
            })

        return findings

    def _check_required_claims(self, payload: Dict, token_type: str) -> List[Dict]:
        """Vérifie la présence des claims requis selon le type de token."""
        findings = []

        # Claims standards JWT
        standard_claims = ["iss", "sub", "aud", "exp", "iat"]

        # Vérifier iss (issuer)
        if "iss" not in payload:
            findings.append({
                "type": "MISSING_ISS_CLAIM",
                "severity": "LOW",
                "description": "Le claim 'iss' (issuer) est absent. Impossible de vérifier l'émetteur.",
                "owasp": "MASVS-AUTH-1"
            })

        # Vérifier sub (subject)
        if "sub" not in payload:
            findings.append({
                "type": "MISSING_SUB_CLAIM",
                "severity": "LOW",
                "description": "Le claim 'sub' (subject) est absent. L'identité du sujet n'est pas explicite.",
                "owasp": "MASVS-AUTH-1"
            })

        # Vérifier aud (audience)
        if "aud" not in payload:
            findings.append({
                "type": "MISSING_AUD_CLAIM",
                "severity": "LOW",
                "description": "Le claim 'aud' (audience) est absent. Le token peut être utilisé par d'autres services.",
                "owasp": "MASVS-AUTH-1",
                "impact": "Risque de confusion entre services (confused deputy)."
            })

        # Claims spécifiques refresh token
        if token_type == "refresh":
            if "jti" not in payload:
                findings.append({
                    "type": "MISSING_JTI_CLAIM",
                    "severity": "MEDIUM",
                    "description": "Le claim 'jti' (JWT ID) est absent sur le refresh token.",
                    "owasp": "MASVS-AUTH-5",
                    "impact": "Impossible d'implémenter la révocation individuelle ou la détection de réutilisation."
                })

        return findings

    def _calculate_risk_level(self, findings: List[Dict]) -> str:
        """Calcule le niveau de risque global basé sur les findings."""
        if not findings:
            return "LOW"

        severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        total_score = sum(severity_scores.get(f.get("severity", "LOW"), 0) for f in findings)

        if total_score >= 8 or any(f.get("severity") == "CRITICAL" for f in findings):
            return "CRITICAL"
        elif total_score >= 5 or any(f.get("severity") == "HIGH" for f in findings):
            return "HIGH"
        elif total_score >= 2:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Génère des recommandations basées sur les findings."""
        recommendations = []

        finding_types = {f["type"] for f in findings}

        if "MISSING_EXP_CLAIM" in finding_types:
            recommendations.append("Ajouter un claim 'exp' avec une expiration raisonnable (max 24h pour access token).")

        if "EXCESSIVE_TOKEN_LIFETIME" in finding_types:
            recommendations.append("Réduire la durée de vie des tokens. Utiliser des refresh tokens pour les sessions longues.")

        if "MISSING_IAT_CLAIM" in finding_types:
            recommendations.append("Ajouter un claim 'iat' pour tracer l'émission du token.")

        if "ALG_NONE_VULNERABILITY" in finding_types:
            recommendations.append("Utiliser un algorithme de signature fort (RS256, ES256, ou HS256 avec secret fort).")

        if "MISSING_JTI_CLAIM" in finding_types:
            recommendations.append("Ajouter un claim 'jti' unique pour permettre la révocation des refresh tokens.")

        if "MISSING_AUD_CLAIM" in finding_types:
            recommendations.append("Ajouter un claim 'aud' pour restreindre l'usage du token à un public spécifique.")

        if not recommendations:
            recommendations.append("La configuration des tokens semble correcte. Continuer à surveiller les bonnes pratiques.")

        return recommendations

    def _format_duration(self, seconds: int) -> str:
        """Formate une durée en secondes en format lisible."""
        if seconds < 60:
            return f"{seconds} secondes"
        elif seconds < 3600:
            return f"{seconds // 60} minutes"
        elif seconds < 86400:
            return f"{seconds // 3600} heures"
        else:
            days = seconds // 86400
            return f"{days} jours"

    def analyze_multiple_tokens(self, tokens: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Analyse une collection de tokens (ex: séquence access + refresh).

        Args:
            tokens: Liste de dicts {"token": "...", "type": "access|refresh"}

        Returns:
            Analyse globale avec corrélations
        """
        results = {
            "tokens": [],
            "findings": [],
            "rotation_detected": False,
            "refresh_token_security": "UNKNOWN",
            "overall_risk": "LOW"
        }

        for token_info in tokens:
            analysis = self.analyze_token(
                token_info["token"],
                token_info.get("type", "access")
            )
            results["tokens"].append(analysis)
            results["findings"].extend(analysis.get("findings", []))

        # Détection de rotation (si plusieurs tokens de même type)
        access_tokens = [t for t in results["tokens"] if t["token_type"] == "access"]
        if len(access_tokens) >= 2:
            # Vérifier si les jti sont différents
            jtis = [t["claims"].get("jti") for t in access_tokens if t["claims"].get("jti")]
            if len(set(jtis)) > 1:
                results["rotation_detected"] = True

        # Évaluer la sécurité des refresh tokens
        refresh_tokens = [t for t in results["tokens"] if t["token_type"] == "refresh"]
        if refresh_tokens:
            refresh_findings = refresh_tokens[0].get("findings", [])
            if any(f["type"] == "MISSING_JTI_CLAIM" for f in refresh_findings):
                results["refresh_token_security"] = "WEAK"
            elif any(f["severity"] in ["CRITICAL", "HIGH"] for f in refresh_findings):
                results["refresh_token_security"] = "AT_RISK"
            else:
                results["refresh_token_security"] = "GOOD"

        # Risque global
        if any(f.get("severity") == "CRITICAL" for f in results["findings"]):
            results["overall_risk"] = "CRITICAL"
        elif any(f.get("severity") == "HIGH" for f in results["findings"]):
            results["overall_risk"] = "HIGH"
        elif results["findings"]:
            results["overall_risk"] = "MEDIUM"

        return results
