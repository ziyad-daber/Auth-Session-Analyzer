# Auth & Session Analyzer - Development Guide

**Project:** Auth & Session Security Analyzer
**Domain:** Android Security / Authentication / Session Management
**Last Updated:** 2026-04-28

---

## Project Objective

Build an advanced audit tool for authentication and session vulnerabilities in Android applications.

**Core Focus:**
- Token storage security
- Refresh token handling
- Session invalidation (logout)
- Session timeout/expiration
- Session fixation risks

**MASVS Coverage:** Chapters 4, 6, 7, 12, 14 - Labs 3, 4, 5

---

## Architecture Overview

```
auth-session-validator/
├── backend/                 # FastAPI (Python)
│   ├── main.py             # API entry point
│   ├── config.py           # Configuration
│   ├── static_analyzer/    # JADX-based static analysis
│   ├── dynamic_analyzer/   # Proxy + Frida instrumentation
│   ├── active_validator/   # Attack tests
│   ├── correlation_engine/ # ML + scoring + AI
│   ├── masvs/              # MASVS compliance
│   └── report_generator/   # PDF reports
├── frontend/               # Dashboard (HTML/JS/CSS)
├── uploads/                # Temporary storage
└── reports/                # Generated PDFs
```

---

## Development Quick Start

### Environment Setup

```bash
# Navigate to project
cd auth-session-validator

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
# Start backend (port 8001)
python backend/main.py

# Access dashboard
http://localhost:8000
```

### Test Application

Default target: **InsecureBankv2** APK
Backend server: `AndroLabServer/server_v3.py` (auto-starts)
Default credentials: `admin` / `admin@123`

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `backend/main.py` | API endpoints, orchestration |
| `backend/config.py` | Paths, ports, settings |
| `backend/dynamic_analyzer/proxy_manager.py` | MITM proxy control |
| `backend/dynamic_analyzer/frida_manager.py` | Frida instrumentation |
| `backend/active_validator/jwt_attacker.py` | JWT attack tests |
| `backend/active_validator/session_tester.py` | Session tests |
| `backend/correlation_engine/token_analyzer.py` | JWT analysis |
| `backend/correlation_engine/risk_scorer.py` | Risk scoring + MASVS |
| `backend/report_generator/pdf_generator.py` | PDF export |
| `backend/masvs/checklist_generator.py` | MASVS checklist generation |
| `backend/static_analyzer/storage_scanner.py` | Storage security analysis |

---

## Development Guidelines

### Code Style

- **Python:** Type hints, docstrings for public methods
- **Naming:** Snake case for Python, PascalCase for classes
- **Error Handling:** Return structured error responses, don't crash

### API Design

```python
# Endpoint pattern
@app.post("/api/{domain}/{action}")
async def action_handler(param: str = None):
    try:
        result = handler.analyze(param)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

### Finding Format

```python
{
    "type": "JWT_TOKEN_LEAK",
    "severity": "HIGH",  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    "description": "Human-readable description",
    "owasp": "MASVS-AUTH-1",
    "impact": "Exploit impact description",
    "file": "path/to/file.java",
    "snippet": "Code context"
}
```

### Session State

Persist state in `session_data.json`:

```python
from backend.main import session_state, save_session

session_state["static_findings"] = findings
save_session(session_state)
```

---

## Testing

### Manual Testing Flow

1. Upload APK via dashboard
2. Wait for static analysis completion
3. Start proxy + Frida (auto or manual)
4. Perform login in Android app
5. Run attack tests from dashboard
6. Review findings + export PDF

### API Testing

```bash
# Check system status
curl http://localhost:8001/api/status

# Static analysis
curl -X POST -F "apk=@app.apk" http://localhost:8001/api/analyze/static

# Get traffic
curl http://localhost:8001/api/proxy/traffic

# Run JWT none attack
curl -X POST "http://localhost:8001/api/attack/session/jwt_none"

# Generate PDF
curl http://localhost:8001/api/report/pdf --output report.pdf
```

---

## MASVS Reference

### Authentication (Chapter 4)

| Requirement | Test |
|-------------|------|
| V4.1 Password Policy | Bruteforce lockout test |
| V4.2 Username Enumeration | Enumeration test |
| V4.4 Session Management | Fixation + timeout tests |
| V4.5 Token Security | JWT tests + rotation |

### Session Management (Chapter 6)

| Requirement | Test |
|-------------|------|
| V6.1 Session ID Quality | Entropy analysis |
| V6.2 Session Expiration | Timeout test |
| V6.3 Session Invalidation | Token replay test |
| V6.4 Session Fixation | Fixation test |

### Data Storage (Chapter 7)

| Requirement | Test |
|-------------|------|
| V7.1 Secure Storage | Secret scanner + storage scanner |
| V7.2 Crypto Usage | Weak crypto detection |
| V7.3 Sensitive Data | Token/credential detection |

### Network (Chapter 12)

| Requirement | Test |
|-------------|------|
| V12.1 HTTPS | Insecure HTTP detection |
| V12.2 Certificate Validation | Frida SSL bypass |
| V12.3 Pinning | Pinning bypass scripts |

---

## Vulnerability Patterns

### Static Analysis Patterns

```python
patterns = {
    "JWT_TOKEN_LEAK": r"eyJ[a-zA-Z0-9._-]{10,}",
    "HARDCODED_SECRET": r"(?i)(password|secret|key|api_key|token|auth|pwd)\s*=\s*['\"]([^'\"]{4,})['\"]",
    "WEAK_CRYPTO": r"Cipher\.getInstance\s*\(\s*['\"](DES|AES/ECB|RC4)['\"]",
    "SQL_INJECTION": r"\.rawQuery\s*\(\s*['\"].*?\s*\+\s*\w+",
    "INSECURE_HTTP": r"http://(?!(schemas\.android\.com|...))[a-zA-Z0-9./_-]+"
}
```

### Dynamic Analysis Triggers

- JWT in HTTP headers - `Authorization: Bearer <token>`
- Credentials in POST body - `username=...&password=...`
- Session ID in cookies - `sessionid=...`

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| JADX not found | Check `JADX_PATH` in `config.py` |
| Proxy won't start | Port 8080 may be in use |
| Frida not connecting | Run `adb root` + restart frida-server |
| No traffic captured | Configure Android proxy + install mitm cert |
| Backend path errors | Update paths in `config.py` |

### ADB Reverse (Emulator Networking)

```bash
adb reverse tcp:8888 tcp:8888  # Target server
adb reverse tcp:8001 tcp:8001  # Backend
adb reverse tcp:8080 tcp:8080  # Proxy
```

Use `127.0.0.1` in Android app config after reverse.

---

## Development Checklist

### Before Committing

- [ ] No hardcoded absolute paths (use `config.py`)
- [ ] Error handling for file operations
- [ ] API endpoints return consistent JSON format
- [ ] New findings include OWASP/MASVS tags
- [ ] Timeline events for significant actions

### Adding New Features

1. Create module in appropriate package
2. Add API endpoint in `backend/main.py`
3. Update frontend (`app.js` + `index.html`)
4. Add to MASVS mapping in `risk_scorer.py`
5. Update `STATUS.md` and this file

---

## Security Considerations

### Safe Defaults

- Attack tests target localhost only
- No external API calls without user config
- Uploaded APKs stored temporarily, deleted on reset
- Findings never leave local machine

### User Data Protection

- `users_db.json` stores hashed passwords (SHA256)
- Session data in `session_data.json` is local-only
- PDF reports generated on-demand, not persisted

---

## Additional Resources

- [STATUS.md](./STATUS.md) - Feature tracking
- [AGENTS.md](./AGENTS.md) - Agent architecture
- [README.md](./README.md) - User quick start
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues
- [OWASP MASVS](https://owasp.org/www-project-mobile-app-security/)
- [MSTG Testing Guide](https://github.com/OWASP/owasp-mstg)

---

## Implementation Status

All core features implemented as of 2026-04-28:

1. Token Lifetime Analyzer - `/api/analyze/token/lifetime`
2. Token Rotation Tester - `/api/analyze/token/rotation`
3. MASVS Checklist Generator - `/api/masvs/generate-checklist`
4. Security Acceptance Criteria - `/api/masvs/acceptance-criteria`
5. Storage Security Scanner - `/api/analyze/storage`

### Future Enhancements (Optional)

1. OAuth2 Security Tests - PKCE, redirect URI validation, state parameter
2. Root Detection Tests - Chapter 14 compliance
3. Tamper Detection - APK integrity verification
