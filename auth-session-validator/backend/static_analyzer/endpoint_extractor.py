import os
import re
from typing import List, Dict, Any, Optional

# --- Patterns pour détecter les URLs et endpoints ---
URL_PATTERNS = [
    r'https?://[a-zA-Z0-9./_-]+',
]

AUTH_KEYWORDS = [
    "login", "signin", "sign_in", "auth", "authenticate",
    "token", "oauth", "jwt", "session", "logout", "signout",
    "password", "verify", "validate",
]

def extract_auth_endpoints(decompiled_dir: str) -> Dict[str, Any]:
    """
    Extraits les endpoints d'authentification depuis le code décompilé.
    """
    found_urls = set()
    auth_endpoints = []
    
    print(f"[*] Analyse des endpoints dans {decompiled_dir}...")
    
    try:
        for root, _, files in os.walk(decompiled_dir):
            for file_name in files:
                if file_name.endswith(('.java', '.xml', '.kt')):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern in URL_PATTERNS:
                                matches = re.findall(pattern, content)
                                for url in matches:
                                    # Éviter les URLs de schémas Android standard
                                    if "schemas.android.com" in url or "www.w3.org" in url:
                                        continue
                                        
                                    found_urls.add(url)
                                    
                                    # Détecter si c'est un endpoint d'auth
                                    is_auth = any(kw in url.lower() for kw in AUTH_KEYWORDS)
                                    if is_auth:
                                        auth_endpoints.append({
                                            "url": url,
                                            "file": file_name,
                                            "is_auth": True
                                        })
                    except: continue
    except Exception as e:
        print(f"Error extracting endpoints: {e}")

    # Déduire l'URL de base la plus probable (celle qui revient souvent ou contient 'api')
    base_url = None
    if found_urls:
        # On prend la première URL qui semble être une racine (finit par / ou n'a pas de long path)
        candidate_urls = [u for u in found_urls if u.count('/') <= 4]
        if candidate_urls:
            base_url = sorted(candidate_urls, key=len)[0]

    return {
        "base_url": base_url,
        "auth_endpoints": auth_endpoints[:10], # Limiter pour l'instant
        "all_urls": list(found_urls)[:20]
    }

def guess_logout_endpoint(auth_endpoints: List[Dict]) -> Optional[str]:
    for e in auth_endpoints:
        if "logout" in e['url'].lower() or "signout" in e['url'].lower():
            return e['url']
    return None

def guess_protected_endpoint(auth_endpoints: List[Dict]) -> Optional[str]:
    for e in auth_endpoints:
        if any(kw in e['url'].lower() for kw in ["account", "profile", "dashboard", "user"]):
            return e['url']
    return None
