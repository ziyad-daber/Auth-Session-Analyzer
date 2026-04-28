"""
dynamic_analyzer/jwt_interceptor.py
─────────────────────────────────────
Extraction et analyse des tokens JWT interceptés dans le trafic réseau.
"""

import re
import base64
import json
from typing import List, Dict, Any, Optional

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

def _base64url_decode(input_str: str) -> bytes:
    """Décode une chaîne base64url en ajoutant le padding si nécessaire."""
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)

def decode_jwt_parts(token: str) -> Dict[str, Any]:
    """
    Décode les parties header et payload d'un JWT sans vérifier la signature.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Format JWT invalide")
    
    header_b64, payload_b64, signature = parts
    
    try:
        header_json = _base64url_decode(header_b64).decode('utf-8')
        payload_json = _base64url_decode(payload_b64).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        return {
            "header": header,
            "payload": payload,
            "signature": signature,
            "raw": token
        }
    except Exception as e:
        raise ValueError(f"Erreur de décodage JWT : {e}")

def find_jwt_in_string(text: str) -> List[str]:
    """Cherche tous les tokens JWT dans une chaîne de caractères."""
    return JWT_REGEX.findall(text)

def extract_jwts_from_traffic(captured_data: dict) -> List[Dict[str, Any]]:
    """
    Extrait et décode tous les tokens JWT depuis les données capturées par le proxy.
    """
    enriched = []
    tokens = captured_data.get("jwt_tokens", [])
    
    for raw_token in tokens:
        try:
            decoded = decode_jwt_parts(raw_token)
            enriched.append({
                "token": raw_token,
                "header": decoded["header"],
                "payload": decoded["payload"],
                "severity": "INFO"
            })
        except:
            continue
            
    return enriched

def is_same_token(token1: str, token2: str) -> bool:
    """Compare deux tokens JWT via leurs payloads."""
    try:
        p1 = decode_jwt_parts(token1)["payload"]
        p2 = decode_jwt_parts(token2)["payload"]
        
        # On compare les identifiants uniques ou le sujet si disponible
        for key in ["jti", "sub"]:
            if key in p1 and key in p2:
                return p1[key] == p2[key]
        
        return p1 == p2
    except:
        return False
