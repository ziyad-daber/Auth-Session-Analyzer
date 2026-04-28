"""
backend/correlation_engine/ai_recommender.py
Générateur de recommandations expertes via Gemini 1.5
"""

import json
import logging
import os
import google.generativeai as genai
import requests
from config import GEMINI_API_KEY, AI_PROVIDER, AI_MODEL, OLLAMA_URL

logger = logging.getLogger(__name__)

class AIRecommender:
    def __init__(self):
        self.provider = AI_PROVIDER
        self.enabled = (self.provider != "none")
        self._cache = None
        
        if self.provider == "gemini" and GEMINI_API_KEY:
            try:
                genai.configure(api_key=GEMINI_API_KEY)
                self.model = genai.GenerativeModel(model_name=AI_MODEL)
            except: self.enabled = False
        
    def generate_remediations(self, findings):
        if not findings or not self.enabled:
            return []

        prompt = self._build_prompt(findings)

        if self.provider == "ollama":
            return self._call_ollama(prompt)
        elif self.provider == "gemini":
            return self._call_gemini(prompt)
        return []

    def _call_ollama(self, prompt):
        """Appel vers l'IA locale Ollama."""
        try:
            payload = {
                "model": AI_MODEL,
                "prompt": prompt + "\nREPONDRE UNIQUEMENT EN JSON VALIDE. NE PAS AJOUTER DE TEXTE AVANT OU APRES.",
                "stream": False,
                "format": "json"
            }
            response = requests.post(OLLAMA_URL, json=payload, timeout=60)
            if response.status_code == 200:
                result = response.json()
                return self._parse_ai_response(result.get("response", ""))
            return []
        except Exception as e:
            logger.error(f"Erreur Ollama : {e}")
            return []

    def _call_gemini(self, prompt):
        """Appel vers Google Gemini."""
        try:
            response = self.model.generate_content(prompt)
            return self._parse_ai_response(response.text)
        except Exception as e:
            logger.error(f"Erreur Gemini : {e}")
            return []

    def _build_prompt(self, findings):
        """Construit un prompt riche incluant les snippets de code."""
        context = []
        for f in findings:
            context.append({
                "vulnerability": f.get("type", "UNKNOWN"),
                "severity": f.get("severity", "MEDIUM"),
                "description": f.get("description", ""),
                "snippet": f.get("snippet", "Code non disponible")
            })

        prompt = f"""Analyse ces vulnérabilités Android et génère 3 recommandations prioritaires.
        
DONNÉES D'AUDIT :
{json.dumps(context, indent=2)}

REQUIS POUR CHAQUE RECOMMANDATION :
1. "title": Titre court (ex: Hardcoded Secret)
2. "risk": Explication du risque métier et technique.
3. "action": Étapes précises de remédiation.
4. "code_fix": Exemple de code sécurisé (Kotlin ou Java) ou configuration XML.
5. "priority": CRITIQUE, HAUTE ou MOYENNE.

RÉPONDRE UNIQUEMENT EN JSON (ARRAY D'OBJETS)."""
        return prompt

    def _parse_ai_response(self, content):
        """Parseur robuste pour extraire le JSON."""
        try:
            clean = content.replace("```json", "").replace("```", "").strip()
            start = clean.find('[')
            end = clean.rfind(']') + 1
            if start != -1 and end != 0:
                return json.loads(clean[start:end])
            return json.loads(clean)
        except Exception as e:
            logger.error(f"Erreur parsing AI : {e}")
            return []
