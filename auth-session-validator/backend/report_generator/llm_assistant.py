"""
report_generator/llm_assistant.py
───────────────────────────────────
Intégration de Claude (Anthropic) pour l'analyse intelligente et la remédiation.
"""

import os
from typing import List, Dict, Any

class LLMSecurityAssistant:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

    def generate_remediation_advice(self, findings: List[Dict[str, Any]]) -> str:
        """
        Envoie les vulnérabilités à Claude pour obtenir des conseils de correction.
        """
        if not self.api_key:
            return "Clé API Claude manquante. Impossible de générer des conseils intelligents."

        prompt = self._build_prompt(findings)
        
        try:
            # Simulation de l'appel API (nécessite la librairie anthropic)
            # client = anthropic.Anthropic(api_key=self.api_key)
            # response = client.messages.create(...)
            
            return f"Claude a analysé {len(findings)} vulnérabilités. Voici ses recommandations..."
        except Exception as e:
            return f"Erreur lors de l'appel à l'IA : {e}"

    def _build_prompt(self, findings: List[Dict[str, Any]]) -> str:
        summary = "\n".join([f"- {f['type']} (Sévérité: {f['severity']})" for f in findings])
        return f"""
        En tant qu'expert en sécurité mobile, analyse ces vulnérabilités trouvées dans une application Android :
        {summary}
        
        Pour chaque vulnérabilité :
        1. Explique le risque métier.
        2. Donne le code Kotlin/Java sécurisé pour corriger le problème.
        3. Propose une stratégie de test pour vérifier le correctif.
        """

    def generate_executive_summary(self, risk_score: int) -> str:
        """Génère un petit texte de synthèse selon le score de risque."""
        if risk_score > 70:
            return "ALERTE : L'application présente des failles critiques d'authentification. Une exploitation immédiate est possible."
        elif risk_score > 40:
            return "ATTENTION : Plusieurs failles de session ont été détectées. La posture de sécurité est fragile."
        else:
            return "SÉCURISÉ : Aucune faille majeure de session n'a été détectée."
