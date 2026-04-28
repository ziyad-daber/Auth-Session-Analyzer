"""
correlation_engine/risk_scorer.py
───────────────────────────────────
Calcul du score de risque basé sur le barème défini dans le projet.
"""

from typing import List, Dict, Any

class RiskScorer:
    def __init__(self):
        # Barème de points précis
        self.points_map = {
            "JWT_BYPASS": 40,
            "JWT_Secret_Cracked": 30,
            "SESSION_FIXATION": 30,
            "LOCKOUT_VULNERABLE": 20,
            "ENUMERATION_VULNERABLE": 20,
            "INSECURE_HTTP": 15,
            "HARDCODED_SECRET": 15,
            "JWT_TOKEN_LEAK": 15,
            "ML_TRAFFIC_ANOMALY": 10,
            "DEBUG_MODE_ENABLED": 5
        }

    def calculate_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calcul du score final et niveau de risque."""
        total_points = 0
        confirmed_types = set()

        for f in findings:
            ftype = f.get("type")
            if ftype in self.points_map:
                total_points += self.points_map[ftype]
                confirmed_types.add(ftype)

        # Niveaux de risque
        if total_points >= 80: level = "CRITIQUE"
        elif total_points >= 40: level = "ÉLEVÉ"
        elif total_points >= 15: level = "MOYEN"
        else: level = "FAIBLE"

        return {
            "score": total_points,
            "level": level,
            "max_score": 150,
            "vulnerabilities_count": len(confirmed_types),
            "methodology": "Basé sur l'OWASP MASVS v2.0. Chaque type de vulnérabilité unique ajoute des points selon sa sévérité (Critique: 40pt, Élevé: 20-30pt, Moyen: 10-15pt)."
        }

    def get_score_breakdown(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Retourne le détail des points pour chaque vulnérabilité unique."""
        breakdown = []
        confirmed_types = set()
        
        for f in findings:
            ftype = f.get("type")
            if ftype in self.points_map and ftype not in confirmed_types:
                breakdown.append({
                    "type": ftype,
                    "points": self.points_map[ftype],
                    "owasp": self.get_masvs_mapping(ftype),
                    "severity": f.get("severity", "MEDIUM")
                })
                confirmed_types.add(ftype)
        return breakdown

    def get_masvs_mapping(self, f_type: str) -> str:
        """Mapping OWASP MASVS v2.0 (MSTG)."""
        mapping = {
            "JWT_BYPASS": "MASVS-AUTH-1 (MSTG-AUTH-1)",
            "SESSION_FIXATION": "MASVS-AUTH-2 (MSTG-AUTH-6)",
            "TOKEN_REPLAY": "MASVS-AUTH-3 (MSTG-AUTH-6)",
            "JWT_TOKEN_LEAK": "MASVS-AUTH-1 (MSTG-AUTH-1)",
            "HARDCODED_SECRET": "MASVS-STORAGE-1 (MSTG-STORAGE-1)",
            "INSECURE_HTTP": "MASVS-NETWORK-1 (MSTG-NETWORK-1)",
            "LOCKOUT_VULNERABLE": "MASVS-AUTH-5 (MSTG-AUTH-2)",
            "ENUMERATION_VULNERABLE": "MASVS-AUTH-5 (MSTG-AUTH-2)",
            "ML_TRAFFIC_ANOMALY": "MASVS-RESILIENCE-1"
        }
        return mapping.get(f_type, "MASVS-GENERIC")
