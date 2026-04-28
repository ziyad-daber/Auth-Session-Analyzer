"""
correlation_engine/ml_analyzer.py
───────────────────────────────────
Détection d'anomalies de session via Machine Learning (Isolation Forest).
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any

class SessionMLAnalyzer:
    def __init__(self):
        # Modèle pour détecter les "outliers" (anomalies)
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False

    def prepare_data(self, flows: List[Dict[str, Any]]):
        """
        Transforme les flux de trafic en vecteurs pour le ML.
        Features : [taille_req, taille_res, delay, entropy_jwt, is_auth]
        """
        data = []
        for f in flows:
            req_size = len(str(f.get("request", {}).get("body", "")))
            res_size = len(str(f.get("response", {}).get("body", ""))) if f.get("response") else 0
            
            # Simulation d'entropie si JWT présent
            entropy = 0
            if "eyJ" in str(f.get("request", {}).get("headers", "")):
                entropy = 4.5 # Valeur moyenne pour un JWT
            
            vector = [
                req_size,
                res_size,
                1 if f.get("is_auth") else 0,
                entropy,
                f.get("response", {}).get("status_code", 200) if f.get("response") else 0
            ]
            data.append(vector)
        return np.array(data) if data else np.zeros((0, 5))

    def analyze_traffic(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Détecte les anomalies dans le flux de trafic."""
        if not flows or len(flows) < 10:
            return [] # Pas assez de données pour être pertinent
            
        X = self.prepare_data(flows)
        
        # Entraînement "on-the-fly" sur la session actuelle (Unsupervised)
        try:
            self.model.fit(X)
            predictions = self.model.predict(X)
            
            anomalies = []
            for i, pred in enumerate(predictions):
                if pred == -1: # Anomalie détectée
                    flow = flows[i]
                    anomalies.append({
                        "type": "ML_TRAFFIC_ANOMALY",
                        "severity": "MEDIUM",
                        "description": f"Comportement réseau inhabituel détecté sur {flow['method']} {flow['url']}",
                        "flow_id": flow['id'],
                        "confidence": "Isolation Forest"
                    })
            return anomalies
        except:
            return []
