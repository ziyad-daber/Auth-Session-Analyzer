"""
config.py — Configuration globale du projet Auth & Session Validator
"""

import os

# ─── Chemins de base ─────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR    = os.path.dirname(BASE_DIR)

UPLOAD_DIR  = os.path.join(ROOT_DIR, "uploads")
REPORTS_DIR = os.path.join(ROOT_DIR, "reports")
TOOLS_DIR   = os.path.join(ROOT_DIR, "tools")
APKS_DIR    = os.path.join(ROOT_DIR, "apks")
LOGS_DIR    = os.path.join(ROOT_DIR, "logs")

# ─── Outils externes ─────────────────────────────────────────────────────────
JADX_PATH   = os.path.join(TOOLS_DIR, "jadx", "jadx-cli", "bin", "jadx.bat")  # Windows
JADX_LINUX  = os.path.join(TOOLS_DIR, "jadx", "jadx-cli", "bin", "jadx")       # Linux/macOS

# ─── Proxy MITM ──────────────────────────────────────────────────────────────
PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 8888

# ─── Paramètres d'analyse ────────────────────────────────────────────────────
MAX_APK_SIZE_MB = 100
SCAN_TIMEOUT    = 300   # secondes
REQUEST_TIMEOUT = 10    # secondes pour les requêtes actives

# ─── Scoring CVSS ────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH":     12,
    "MEDIUM":   6,
    "LOW":      2,
    "INFO":     0,
}

# ─── Intelligence Artificielle ──────────────────────────────────────────────
# Provider options: "gemini", "ollama", "none"
AI_PROVIDER    = os.getenv("AI_PROVIDER", "ollama") 
AI_MODEL       = os.getenv("AI_MODEL", "llama3")

# Gemini Cloud
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyDtpsI5-ec4v6FE5iNwKleo1-PjV8FRty0")

# Ollama Local
OLLAMA_URL     = "http://127.0.0.1:11434/api/generate"

# ─── Créer les dossiers si inexistants ───────────────────────────────────────
for _dir in [UPLOAD_DIR, REPORTS_DIR, LOGS_DIR]:
    os.makedirs(_dir, exist_ok=True)
