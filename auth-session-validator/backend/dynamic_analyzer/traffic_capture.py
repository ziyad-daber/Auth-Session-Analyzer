"""
dynamic_analyzer/traffic_capture.py
─────────────────────────────────────
Parsing et analyse du trafic capturé par le proxy.
Transforme les flux bruts en findings structurés.
"""

from typing import List, Dict, Any
import urllib.parse

def parse_captured_traffic(captured_data: dict) -> List[Dict[str, Any]]:
    """
    Analyse les flux HTTP capturés et identifie les problèmes de sécurité.
    """
    all_findings = []
    flows = captured_data.get("flows", [])
    
    # Mots-clés sensibles
    sensitive_keys = ["password", "pwd", "admin", "secret", "token", "apikey", "card_number", "username", "uname", "login", "email"]

    for flow in flows:
        req = flow["request"]
        res = flow.get("response")
        url = flow["url"]
        flow_id = flow["id"]
        
        # 1. Analyse HTTP vs HTTPS
        is_http = url.startswith("http://")
        
        # 2. Analyse du corps de la requête (POST)
        req_body = req.get("body", "").lower()
        found_sensitive_req = [key for key in sensitive_keys if key in req_body]
        
        if found_sensitive_req:
            if is_http:
                all_findings.append({
                    "flow_id": flow_id,
                    "type": "CLEARTEXT_CREDENTIALS",
                    "severity": "CRITICAL",
                    "description": f"Données sensibles ({', '.join(found_sensitive_req)}) transmises en clair via HTTP !",
                    "owasp": "MASVS-AUTH-1",
                    "url": url,
                    "evidence": req_body[:100]
                })
            else:
                all_findings.append({
                    "flow_id": flow_id,
                    "type": "SENSITIVE_DATA_EXPOSURE",
                    "severity": "MEDIUM",
                    "description": f"Données sensibles détectées dans le corps de la requête.",
                    "owasp": "MASVS-STORAGE-1",
                    "url": url,
                    "evidence": req_body[:100]
                })

        # 3. Analyse du corps de la réponse
        if res:
            res_body = res.get("body", "").lower()
            if "correct credentials" in res_body or "success" in res_body:
                if is_http:
                    all_findings.append({
                        "flow_id": flow_id,
                        "type": "INSECURE_AUTH_CONFIRMATION",
                        "severity": "HIGH",
                        "description": "Confirmation d'authentification réussie transmise sur un canal non chiffré.",
                        "owasp": "MASVS-NETWORK-1",
                        "url": url
                    })

            # Headers de sécurité
            headers = res.get("headers", {})
            header_findings = check_security_headers(headers)
            for hf in header_findings:
                hf["flow_id"] = flow_id
                hf["url"] = url
                all_findings.append(hf)

    return all_findings

def find_sensitive_in_url(url: str) -> List[Dict[str, Any]]:
    """Détecte les données sensibles passées en paramètre GET."""
    findings = []
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    
    sensitive_keys = ["password", "pwd", "secret", "token", "api_key", "apikey"]
    
    for key in params:
        if any(sk in key.lower() for sk in sensitive_keys):
            findings.append({
                "url": url,
                "param": key,
                "value": params[key][0],
                "severity": "HIGH",
                "description": f"Donnée sensible '{key}' trouvée dans l'URL (GET)."
            })
            
    return findings

def check_security_headers(headers: dict) -> List[Dict[str, Any]]:
    """Vérifie la présence des headers de sécurité HTTP."""
    missing = []
    required = {
        "Strict-Transport-Security": "Empêche les connexions HTTP non chiffrées.",
        "X-Content-Type-Options": "Empêche le sniffing de type MIME.",
        "X-Frame-Options": "Protège contre le Clickjacking.",
        "Content-Security-Policy": "Protège contre le XSS."
    }
    
    # Normalisation des headers en minuscules
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for header, desc in required.items():
        if header.lower() not in headers_lower:
            missing.append({
                "type": f"MISSING_{header.upper().replace('-','_')}",
                "header": header,
                "severity": "MEDIUM",
                "description": f"Header de sécurité '{header}' manquant. {desc}",
                "owasp": "MASVS-NETWORK-1"
            })
            
    return missing

def check_insecure_cookies(headers: dict) -> List[Dict[str, Any]]:
    """Analyse les cookies et détecte les mauvaises configurations."""
    findings = []
    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
    
    if set_cookie:
        cookies = [c.strip() for c in set_cookie.split(',')]
        for cookie in cookies:
            issues = []
            if "httponly" not in cookie.lower():
                issues.append("Manque le flag HttpOnly (vulnérable au vol via XSS)")
            if "secure" not in cookie.lower():
                issues.append("Manque le flag Secure (transmis en clair via HTTP)")
                
            if issues:
                findings.append({
                    "type": "INSECURE_COOKIE",
                    "cookie": cookie.split('=')[0],
                    "issues": issues,
                    "severity": "HIGH",
                    "description": f"Cookie mal configuré : {', '.join(issues)}",
                    "owasp": "MASVS-AUTH-3"
                })
                
    return findings
