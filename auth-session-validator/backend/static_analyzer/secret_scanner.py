"""
static_analyzer/secret_scanner.py
───────────────────────────────────
Détection de secrets et credentials hardcodés dans le code décompilé.
Utilise des patterns regex couvrant JWT, API keys, mots de passe, etc.
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any


# ─── Patterns de détection ───────────────────────────────────────────────────
#
# Format : "NOM_VULN": (regex_pattern, severity, cvss_score)
#
PATTERNS: Dict[str, tuple] = {
    "JWT_Token": (
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "CRITICAL", 9.1
    ),
    "Hardcoded_Password": (
        r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{4,})["\']',
        "HIGH", 8.0
    ),
    "Hardcoded_Username": (
        r'(?:username|user|login|uname)\s*[=:]\s*["\']([^"\']{3,})["\']',
        "MEDIUM", 5.5
    ),
    "API_Key": (
        r'(?:api[_-]?key|apikey|api_token)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
        "HIGH", 7.5
    ),
    "AWS_Access_Key": (
        r"AKIA[0-9A-Z]{16}",
        "CRITICAL", 9.5
    ),
    "Google_API_Key": (
        r"AIza[0-9A-Za-z\-_]{35}",
        "HIGH", 8.5
    ),
    "Private_Key": (
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "CRITICAL", 9.8
    ),
    "Bearer_Token": (
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        "HIGH", 8.2
    ),
    "Basic_Auth_Header": (
        r"Basic\s+[A-Za-z0-9+/]{20,}=*",
        "HIGH", 7.8
    ),
    "URL_With_Credentials": (
        r"https?://[^:\"'\s]+:[^@\"'\s]+@[^\s\"']+",
        "CRITICAL", 9.0
    ),
    "Firebase_URL": (
        r"https://[a-z0-9\-]+\.firebaseio\.com",
        "MEDIUM", 5.3
    ),
    "Secret_Key": (
        r'(?:secret[_-]?key|signing[_-]?key|jwt[_-]?secret)\s*[=:]\s*["\']([^"\']{6,})["\']',
        "CRITICAL", 9.2
    ),
}

# Extensions de fichiers à analyser
SCAN_EXTENSIONS = ["*.java", "*.kt", "*.xml", "*.json", "*.properties", "*.gradle", "*.yaml", "*.yml"]


def scan_secrets(decompiled_dir: str) -> List[Dict[str, Any]]:
    """
    Parcourt tous les fichiers du dossier décompilé et détecte les secrets.

    Args:
        decompiled_dir: Chemin vers le dossier jadx

    Returns:
        Liste de findings : [{"type", "file", "line", "match", "severity", "cvss", "phase"}, ...]
    """
    findings = []
    decompiled_path = Path(decompiled_dir)

    if not decompiled_path.exists():
        return []

    for ext in SCAN_EXTENSIONS:
        for file_path in decompiled_path.rglob(ext):
            if not file_path.is_file():
                continue
                
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    for line_num, line in enumerate(lines, 1):
                        for vuln_type, (pattern, severity, cvss) in PATTERNS.items():
                            matches = re.finditer(pattern, line)
                            for match in matches:
                                findings.append({
                                    "type": vuln_type,
                                    "file": str(file_path.relative_to(decompiled_path)),
                                    "line": line_num,
                                    "match": match.group(0),
                                    "severity": severity,
                                    "cvss": cvss,
                                    "phase": "Static Analysis"
                                })
            except Exception as e:
                print(f"Erreur lors de la lecture de {file_path}: {e}")

    # Déduplication simple
    unique_findings = []
    seen = set()
    for f in findings:
        key = (f["type"], f["file"], f["line"], f["match"])
        if key not in seen:
            unique_findings.append(f)
            seen.add(key)

    # Tri par CVSS décroissant
    return sorted(unique_findings, key=lambda x: x["cvss"], reverse=True)


def scan_shared_preferences(decompiled_dir: str) -> List[Dict[str, Any]]:
    """
    Détecte les données sensibles stockées en clair dans SharedPreferences.
    """
    findings = []
    decompiled_path = Path(decompiled_dir)
    
    # Patterns pour SharedPreferences
    SP_PATTERNS = {
        "Insecure_Storage_SP": r'getSharedPreferences\s*\(',
        "Sensitive_SP_Write": r'put(?:String|Int|Long|Boolean)\s*\(\s*["\'](?:token|pass|user|auth|session|key)',
    }

    for file_path in decompiled_path.rglob("*.java"):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "getSharedPreferences" in content:
                    findings.append({
                        "type": "Insecure_Storage_SharedPreferences",
                        "file": str(file_path.relative_to(decompiled_path)),
                        "severity": "MEDIUM",
                        "cvss": 5.5,
                        "description": "Utilisation de SharedPreferences détectée. Vérifier si les données sont chiffrées."
                    })
        except:
            continue
            
    return findings


def scan_logcat_leaks(decompiled_dir: str) -> List[Dict[str, Any]]:
    """
    Détecte les tokens/credentials loggés via Log.d(), Log.e(), System.out.println().
    """
    findings = []
    decompiled_path = Path(decompiled_dir)
    
    LOG_PATTERN = r'Log\.[idvew]\s*\([^,]+,\s*[^)]*(?:token|pass|auth|session|jwt|key|credential)[^)]*\)'

    for file_path in decompiled_path.rglob("*.java"):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                matches = re.finditer(LOG_PATTERN, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        "type": "Log_Sensitive_Data_Leak",
                        "file": str(file_path.relative_to(decompiled_path)),
                        "severity": "MEDIUM",
                        "cvss": 4.5,
                        "description": f"Fuite potentielle de données sensibles dans les logs : {match.group(0)}"
                    })
        except:
            continue
            
    return findings
