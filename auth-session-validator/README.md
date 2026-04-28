# Auth & Session Analyzer

Advanced security audit tool for authentication and session vulnerabilities in Android applications.

## Quick Start

### 1. Environment Setup

```bash
# Navigate to project
cd auth-session-validator

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Backend

```bash
python backend/main.py
```

The server starts on **http://127.0.0.1:8001**

### 3. Access the Dashboard

Open your browser to: **http://localhost:8000**

---

## Features

### Static Analysis (JADX)
- APK decompilation and source code analysis
- Hardcoded secrets, weak crypto, JWT leaks detection
- Endpoint and permission extraction
- Storage security scanning

### Dynamic Analysis (Proxy + Frida)
- HTTP/HTTPS traffic interception
- Frida script injection for SSL pinning bypass
- Real-time JWT token extraction

### Token Security Tests
- **Token Lifetime** (`/api/analyze/token/lifetime`) - Analyzes temporal claims (exp, iat, nbf)
- **Token Rotation** (`/api/analyze/token/rotation`) - Tests refresh token rotation security

### MASVS Compliance
- **Checklist Generator** (`/api/masvs/generate-checklist`) - Generates checklists based on auth type
- **Acceptance Criteria** (`/api/masvs/acceptance-criteria`) - Security acceptance criteria for user stories

### Storage Analysis
- **Storage Scanner** (`/api/analyze/storage`) - Detects insecure storage (SharedPreferences, Logcat, URLs)

### Attack Simulations
- Session fixation
- Session timeout validation
- Concurrent session detection
- Token replay after logout
- JWT alg:none bypass
- JWT secret cracking
- Bruteforce lockout testing
- Username enumeration

---

## Configuration

### Static Analysis (JADX)
- **Path:** `tools/jadx/jadx-cli/bin/jadx.bat` (Windows) or `jadx` (Linux/macOS)
- **Action:** Upload an APK via the dashboard to trigger automatic scanning

### Dynamic Analysis (Proxy)
- MITM proxy runs on port **8080**
- **Android Configuration:** Set your emulator/phone proxy to your PC IP and configured port
- **Certificate:** Visit `mitm.it` on the mobile device to install the CA certificate

### Target Server (InsecureBankv2)
- If testing the `InsecureBankv2` APK, the backend automatically starts the `AndroLabServer` server
- Configure via `TARGET_SERVER_PATH` environment variable

---

## Project Structure

```
auth-session-validator/
├── backend/
│   ├── main.py                     # FastAPI entry point
│   ├── config.py                   # Configuration
│   ├── static_analyzer/            # JADX-based static analysis
│   ├── dynamic_analyzer/           # Proxy + Frida instrumentation
│   ├── active_validator/           # Attack tests
│   ├── correlation_engine/         # ML + scoring + AI
│   ├── masvs/                      # MASVS compliance
│   └── report_generator/           # PDF reports
├── frontend/                       # Dashboard UI
├── uploads/                        # Temporary APK storage
├── reports/                        # Generated PDFs
└── tools/                          # External tools (JADX, Frida)
```

---

## API Endpoints

### Static Analysis
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze/static` | POST | Upload APK and run static analysis |
| `/api/analyze/storage` | POST | Analyze token/sensitive data storage |

### Dynamic Analysis
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/proxy/start` | POST | Start MITM proxy |
| `/api/proxy/traffic` | GET | Get captured traffic |
| `/api/frida/start` | POST | Start Frida instrumentation |

### Token Security
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze/token/lifetime` | POST | Analyze JWT lifetime |
| `/api/analyze/token/rotation` | POST | Test refresh token rotation |

### Session Attacks
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/attack/session/fixation` | POST | Test session fixation |
| `/api/attack/session/timeout` | POST | Test session timeout |
| `/api/attack/session/concurrent` | POST | Test concurrent sessions |
| `/api/attack/token-replay` | POST | Test token replay after logout |

### MASVS Compliance
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/masvs/generate-checklist` | POST | Generate MASVS checklist |
| `/api/masvs/detect-auth-type` | POST | Detect auth type (JWT/OAuth2/Session) |
| `/api/masvs/acceptance-criteria` | POST | Generate acceptance criteria |
| `/api/masvs/checklist/export` | GET | Export checklist (Markdown/JSON) |

### Reports
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/report/pdf` | GET | Generate PDF audit report |

---

## Default Test Credentials

For InsecureBankv2: `admin` / `admin@123`

---

## Requirements

- Python 3.8+
- JADX (for decompilation)
- Frida (for dynamic instrumentation)
- Android device/emulator (for testing)

See `requirements.txt` for Python dependencies.
