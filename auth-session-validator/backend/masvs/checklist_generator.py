"""
backend/masvs/checklist_generator.py
Générateur de checklist de conformité MASVS
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from .masvs_database import MASVS_AUTH_AND_SESSION, get_requirement_details
from .auth_type_detector import AuthTypeDetector


class ChecklistGenerator:
    """
    Génère des checklists de tests de sécurité basées sur MASVS.

    Fonctionnalités :
    - Détection automatique du type d'auth
    - Génération de checklist contextuelle
    - Mapping des findings vers les exigences
    - Score de conformité
    - Export Markdown/JSON
    """

    def __init__(self):
        self.auth_detector = AuthTypeDetector()

    def generate_checklist(
        self,
        static_findings: List[Dict] = None,
        dynamic_findings: List[Dict] = None,
        auth_type: str = None,
        app_name: str = "Application"
    ) -> Dict[str, Any]:
        """
        Génère une checklist complète basée sur l'analyse.

        Args:
            static_findings: Résultats de l'analyse statique
            dynamic_findings: Résultats de l'analyse dynamique
            auth_type: Type d'auth (auto-détecté si None)
            app_name: Nom de l'application

        Returns:
            Checklist structurée
        """
        # Détection automatique si nécessaire
        if auth_type is None and static_findings:
            detection_result = self.auth_detector.analyze_static_findings(static_findings)
            auth_type = detection_result.get("primary_auth_type", "all")

        if auth_type is None:
            auth_type = "all"

        # Récupérer les exigences applicables
        applicable_requirements = self._get_applicable_requirements(auth_type)

        # Générer la checklist
        checklist = {
            "metadata": {
                "app_name": app_name,
                "auth_type": auth_type,
                "generated_at": datetime.now().isoformat(),
                "masvs_version": "2.0",
                "total_requirements": len(applicable_requirements)
            },
            "summary": {
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "not_applicable": 0,
                "compliance_percentage": 0
            },
            "requirements": [],
            "findings_mapping": [],
            "recommendations": []
        }

        # Traiter chaque exigence
        all_checks = []
        for req_id in applicable_requirements:
            req_data = MASVS_AUTH_AND_SESSION.get(req_id, {})
            if not req_data:
                continue

            requirement = {
                "id": req_id,
                "title": req_data.get("title", ""),
                "description": req_data.get("description", ""),
                "lab": req_data.get("lab", ""),
                "status": "not_evaluated",
                "checks": []
            }

            # Traiter chaque check de l'exigence
            for check in req_data.get("checks", []):
                check_result = self._evaluate_check(
                    check,
                    static_findings or [],
                    dynamic_findings or [],
                    auth_type
                )
                requirement["checks"].append(check_result)
                all_checks.append(check_result)

                # Mapper les findings
                if check_result.get("findings"):
                    for finding in check_result["findings"]:
                        checklist["findings_mapping"].append({
                            "requirement": req_id,
                            "check": check["id"],
                            "finding": finding
                        })

            # Déterminer le statut de l'exigence
            requirement["status"] = self._calculate_requirement_status(requirement["checks"])
            checklist["requirements"].append(requirement)

        # Calculer le résumé
        checklist["summary"] = self._calculate_summary(all_checks)

        # Générer les recommandations
        checklist["recommendations"] = self._generate_recommendations(all_checks, auth_type)

        return checklist

    def _get_applicable_requirements(self, auth_type: str) -> List[str]:
        """Retourne les exigences applicables selon le type d'auth."""
        from .masvs_database import AUTH_TYPE_REQUIREMENTS
        return AUTH_TYPE_REQUIREMENTS.get(auth_type, AUTH_TYPE_REQUIREMENTS["all"])

    def _evaluate_check(
        self,
        check: Dict,
        static_findings: List[Dict],
        dynamic_findings: List[Dict],
        auth_type: str
    ) -> Dict[str, Any]:
        """
        Évalue un check spécifique basé sur les findings.

        Returns:
            Résultat de l'évaluation
        """
        result = {
            "id": check.get("id", ""),
            "name": check.get("name", ""),
            "description": check.get("description", ""),
            "test_method": check.get("test_method", "manual"),
            "status": "passed",  # passed, failed, not_applicable, not_evaluated
            "findings": [],
            "evidence": []
        }

        # Chercher les findings liés à ce check
        related_findings = self._find_related_findings(
            check,
            static_findings,
            dynamic_findings
        )

        if related_findings:
            result["findings"] = related_findings

            # Déterminer le statut basé sur la sévérité des findings
            critical_findings = [f for f in related_findings if f.get("severity") in ["CRITICAL", "HIGH"]]
            if critical_findings:
                result["status"] = "failed"
                result["evidence"] = [
                    f"{f.get('type', 'Unknown')}: {f.get('description', '')}"
                    for f in critical_findings
                ]
            else:
                result["status"] = "warning"
                result["evidence"] = [
                    f"{f.get('type', 'Unknown')}: {f.get('description', '')}"
                    for f in related_findings
                ]

        # Checks spécifiques selon la méthode de test
        if check.get("test_method") == "dynamic" and not dynamic_findings:
            result["status"] = "not_evaluated"
            result["note"] = "Analyse dynamique requise"

        return result

    def _find_related_findings(
        self,
        check: Dict,
        static_findings: List[Dict],
        dynamic_findings: List[Dict]
    ) -> List[Dict]:
        """Trouve les findings liés à un check spécifique."""
        related = []

        check_id = check.get("id", "")
        check_name = check.get("name", "").lower()

        # Mapping check -> types de findings
        finding_mappings = {
            "V4.1-3": ["ACCOUNT_LOCKOUT", "BRUTEFORCE"],
            "V4.1-4": ["BRUTEFORCE", "RATE_LIMIT"],
            "V4.2-1": ["ENUMERATION", "USER_ENUMERATION"],
            "V4.4-1": ["SESSION_FIXATION", "SESSION_REGENERATION"],
            "V4.4-2": ["SESSION_FIXATION"],
            "V4.4-3": ["SESSION_TIMEOUT", "IDLE_TIMEOUT"],
            "V4.5-1": ["INSECURE_PREFS", "TOKEN_LEAK", "HARDCODED_SECRET"],
            "V4.5-2": ["INSECURE_HTTP", "CLEARTEXT_TRAFFIC"],
            "V4.5-3": ["MISSING_EXP_CLAIM", "EXCESSIVE_TOKEN_LIFETIME"],
            "V4.5-4": ["TOKEN_ROTATION", "REFRESH_TOKEN"],
            "V6.1-1": ["WEAK_SESSION_ID", "LOW_ENTROPY"],
            "V6.2-1": ["SESSION_TIMEOUT", "ABSOLUTE_TIMEOUT"],
            "V6.2-2": ["IDLE_TIMEOUT"],
            "V6.3-1": ["LOGOUT_INVALIDATION"],
            "V6.3-2": ["TOKEN_REPLAY", "LOGOUT_BYPASS"],
            "V6.4-1": ["SESSION_FIXATION"],
            "V6.4-2": ["SESSION_IN_URL", "URL_REWRITING"],
            "V7.1-1": ["HARDCODED_SECRET", "HARDCODED_PASSWORD", "HARDCODED_KEY"],
            "V7.1-2": ["INSECURE_PREFS", "SHARED_PREFS_TOKEN"],
            "V7.2-1": ["WEAK_CRYPTO", "DES", "RC4", "MD5", "SHA1"],
            "V7.2-2": ["SECURE_RANDOM", "RANDOM_GENERATOR"],
            "V7.3-1": ["LOG_LEAK", "SENSITIVE_LOG"],
            "V7.3-2": ["TOKEN_IN_URL", "CREDENTIAL_IN_URL"],
            "V12.1-1": ["INSECURE_HTTP", "HTTP_ENDPOINT"],
            "V12.2-1": ["SSL_VALIDATION", "CERTIFICATE_VALIDATION"],
            "V12.2-2": ["CUSTOM_TRUSTMANAGER", "SSL_BYPASS"],
            "V12.3-1": ["SSL_PINNING"],
        }

        # Chercher par mapping
        expected_findings = []
        for key, patterns in finding_mappings.items():
            if key == check_id or any(p.lower() in check_name for p in patterns):
                expected_findings.extend(patterns)

        # Chercher dans les findings statiques
        for finding in static_findings:
            finding_type = finding.get("type", "").upper()
            if any(pattern.upper() in finding_type for pattern in expected_findings):
                related.append(finding)
            # Aussi chercher dans la description
            desc = finding.get("description", "").lower()
            if any(p.lower() in desc for p in expected_findings):
                if finding not in related:
                    related.append(finding)

        # Chercher dans les findings dynamiques
        for finding in dynamic_findings:
            finding_type = finding.get("type", "").upper()
            if any(pattern.upper() in finding_type for pattern in expected_findings):
                related.append(finding)

        return related

    def _calculate_requirement_status(self, checks: List[Dict]) -> str:
        """Calcule le statut global d'une exigence."""
        if not checks:
            return "not_evaluated"

        statuses = [c.get("status", "not_evaluated") for c in checks]

        if all(s == "passed" for s in statuses):
            return "passed"
        elif any(s == "failed" for s in statuses):
            return "failed"
        elif any(s == "warning" for s in statuses):
            return "warning"
        elif all(s == "not_evaluated" for s in statuses):
            return "not_evaluated"
        else:
            return "partial"

    def _calculate_summary(self, all_checks: List[Dict]) -> Dict[str, Any]:
        """Calcule le résumé statistique de la checklist."""
        summary = {
            "total_checks": len(all_checks),
            "passed": 0,
            "failed": 0,
            "warning": 0,
            "not_applicable": 0,
            "not_evaluated": 0,
            "compliance_percentage": 0
        }

        for check in all_checks:
            status = check.get("status", "not_evaluated")
            if status in summary:
                summary[status] += 1

        # Calculer le pourcentage de conformité
        evaluated = summary["total_checks"] - summary["not_evaluated"] - summary["not_applicable"]
        if evaluated > 0:
            passed = summary["passed"]
            summary["compliance_percentage"] = round((passed / evaluated) * 100, 1)

        return summary

    def _generate_recommendations(self, all_checks: List[Dict], auth_type: str) -> List[str]:
        """Génère des recommandations basées sur les checks échoués."""
        recommendations = []

        failed_checks = [c for c in all_checks if c.get("status") == "failed"]
        warning_checks = [c for c in all_checks if c.get("status") == "warning"]

        # Recommandations génériques par type d'auth
        type_recommendations = {
            "jwt": [
                "Implémenter la rotation des refresh tokens",
                "Ajouter des claims exp, iat, nbf sur tous les tokens",
                "Utiliser RS256 ou ES256 plutôt que HS256"
            ],
            "session": [
                "Régénérer le session ID après authentification",
                "Implémenter un timeout absolu et idle",
                "Invalider les sessions côté serveur au logout"
            ],
            "oauth2": [
                "Implémenter PKCE pour les clients publics",
                "Valider strictement les redirect URIs",
                "Utiliser le paramètre state pour prévenir CSRF"
            ]
        }

        # Ajouter les recommandations spécifiques
        for check in failed_checks:
            rec = self._get_check_recommendation(check)
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # Ajouter les recommandations de type
        if auth_type in type_recommendations:
            for rec in type_recommendations[auth_type]:
                if rec not in recommendations:
                    recommendations.append(rec)

        return recommendations

    def _get_check_recommendation(self, check: Dict) -> Optional[str]:
        """Retourne une recommandation pour un check échoué."""
        recommendations_map = {
            "V4.1-3": "Implémenter un lockout de compte après 5-10 tentatives échouées",
            "V4.2-1": "Utiliser des messages d'erreur génériques pour login échoué",
            "V4.4-1": "Régénérer le session ID immédiatement après authentification réussie",
            "V4.5-1": "Stocker les tokens dans EncryptedSharedPreferences ou Android Keystore",
            "V4.5-2": "Forcer HTTPS pour toutes les communications, utiliser HSTS",
            "V4.5-3": "Limiter la durée de vie des access tokens à 15-60 minutes maximum",
            "V6.2-1": "Implémenter un timeout absolu de 8-24 heures maximum",
            "V6.3-1": "Invalider le token côté serveur lors du logout",
            "V6.3-2": "Maintenir une blacklist de tokens révoqués",
            "V6.4-1": "Toujours régénérer le session ID après changement de privilèges",
            "V7.1-1": "Externaliser les secrets dans un vault ou BuildConfig",
            "V7.2-1": "Utiliser AES-GCM ou ChaCha20-Poly1305 pour le chiffrement",
            "V12.1-1": "Remplacer tous les endpoints HTTP par HTTPS"
        }

        check_id = check.get("id", "")
        return recommendations_map.get(check_id)

    def export_markdown(self, checklist: Dict[str, Any]) -> str:
        """Exporte la checklist en format Markdown."""
        md = []
        meta = checklist.get("metadata", {})

        md.append(f"# Checklist de Sécurité - {meta.get('app_name', 'Application')}")
        md.append("")
        md.append(f"**Type d'authentification:** {meta.get('auth_type', 'Non détecté')}")
        md.append(f"**Généré le:** {meta.get('generated_at', 'N/A')}")
        md.append(f"**Version MASVS:** {meta.get('masvs_version', '2.0')}")
        md.append("")

        # Résumé
        summary = checklist.get("summary", {})
        md.append("## 📊 Résumé")
        md.append("")
        md.append(f"- **Total checks:** {summary.get('total_checks', 0)}")
        md.append(f"- **Passed:** ✅ {summary.get('passed', 0)}")
        md.append(f"- **Failed:** ❌ {summary.get('failed', 0)}")
        md.append(f"- **Warning:** ⚠️ {summary.get('warning', 0)}")
        md.append(f"- **Conformité:** {summary.get('compliance_percentage', 0)}%")
        md.append("")

        # Exigences
        md.append("## 📋 Exigences Détaillées")
        md.append("")

        for req in checklist.get("requirements", []):
            status_icon = {
                "passed": "✅",
                "failed": "❌",
                "warning": "⚠️",
                "partial": "🔶",
                "not_evaluated": "⏸️"
            }.get(req.get("status", ""), "❓")

            md.append(f"### {status_icon} {req.get('id')} - {req.get('title', '')}")
            md.append(f"*{req.get('description', '')}*")
            md.append(f"_{req.get('lab', '')}_")
            md.append("")

            for check in req.get("checks", []):
                check_icon = {
                    "passed": "✅",
                    "failed": "❌",
                    "warning": "⚠️",
                    "not_evaluated": "⏸️"
                }.get(check.get("status", ""), "❓")

                md.append(f"- {check_icon} **{check.get('name', '')}**")
                md.append(f"  - {check.get('description', '')}")

                if check.get("evidence"):
                    md.append(f"  - **Preuves:**")
                    for ev in check.get("evidence", []):
                        md.append(f"    - {ev}")
                md.append("")

        # Recommandations
        md.append("## 💡 Recommandations")
        md.append("")
        for i, rec in enumerate(checklist.get("recommendations", []), 1):
            md.append(f"{i}. {rec}")

        return "\n".join(md)

    def export_json(self, checklist: Dict[str, Any], pretty: bool = True) -> str:
        """Exporte la checklist en format JSON."""
        if pretty:
            return json.dumps(checklist, indent=2, ensure_ascii=False)
        return json.dumps(checklist, ensure_ascii=False)

    def generate_security_acceptance_criteria(
        self,
        checklist: Dict[str, Any],
        user_story: str = ""
    ) -> List[Dict[str, str]]:
        """
        Génère des critères d'acceptation de sécurité pour des user stories.

        Args:
            checklist: Checklist générée
            user_story: Description de la user story

        Returns:
            Liste de critères d'acceptation
        """
        criteria = []

        # Critères génériques basés sur les exigences échouées
        failed_reqs = [
            r for r in checklist.get("requirements", [])
            if r.get("status") == "failed"
        ]

        for req in failed_reqs:
            req_id = req.get("id", "")
            req_title = req.get("title", "")

            criteria.append({
                "requirement": req_id,
                "title": req_title,
                "criterion": f"L'application doit satisfaire {req_id} ({req_title})",
                "verification": req.get("lab", "Vérification manuelle requise"),
                "priority": "HIGH"
            })

        # Ajouter des critères spécifiques selon le type d'auth
        auth_type = checklist.get("metadata", {}).get("auth_type", "")

        standard_criteria = {
            "jwt": [
                {
                    "requirement": "GENERIC-JWT-1",
                    "title": "Token Expiration",
                    "criterion": "Les access tokens expirent après ≤ 24 heures",
                    "verification": "Analyse statique du claim 'exp'",
                    "priority": "HIGH"
                },
                {
                    "requirement": "GENERIC-JWT-2",
                    "title": "Secure Storage",
                    "criterion": "Les tokens sont stockés dans EncryptedSharedPreferences",
                    "verification": "Revue de code + analyse statique",
                    "priority": "HIGH"
                }
            ],
            "session": [
                {
                    "requirement": "GENERIC-SESSION-1",
                    "title": "Session Regeneration",
                    "criterion": "Le session ID est régénéré après authentification",
                    "verification": "Test dynamique de fixation",
                    "priority": "CRITICAL"
                },
                {
                    "requirement": "GENERIC-SESSION-2",
                    "title": "Logout Invalidation",
                    "criterion": "Le logout invalide la session côté serveur",
                    "verification": "Test de replay après logout",
                    "priority": "HIGH"
                }
            ]
        }

        if auth_type in standard_criteria:
            criteria.extend(standard_criteria[auth_type])

        return criteria
