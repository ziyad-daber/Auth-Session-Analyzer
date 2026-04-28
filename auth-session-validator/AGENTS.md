# Auth & Session Analyzer - Agent Configuration

**Project:** Auth & Session Security Analyzer
**Version:** 1.0
**Last Updated:** 2026-04-28

---

## Agent System Overview

This project uses a multi-agent architecture for security analysis. Each agent is responsible for a specific domain of the authentication and session security audit.

---

## Agent Definitions

### 1. Static Analysis Agent

**Responsibility:** Analyze APK source code for security vulnerabilities

**Triggers:**
- APK upload via `/api/analyze/static`
- Manual re-scan request

**Capabilities:**
- JADX decompilation
- Pattern-based vulnerability detection
- Endpoint extraction
- Manifest analysis
- Permission checking
- Secret/cryptographic key detection
- Storage security scanning

**Output:** Static findings list with severity, OWASP tags, file references

**Files:**
- `backend/static_analyzer/secret_scanner.py`
- `backend/static_analyzer/endpoint_extractor.py`
- `backend/static_analyzer/manifest_analyzer.py`
- `backend/static_analyzer/permission_checker.py`
- `backend/static_analyzer/storage_scanner.py`

---

### 2. Dynamic Analysis Agent

**Responsibility:** Monitor runtime behavior and network traffic

**Triggers:**
- Proxy start via `/api/proxy/start`
- Frida start via `/api/frida/start`
- Traffic capture automation

**Capabilities:**
- MITM traffic interception
- JWT token extraction
- Frida instrumentation
- SSL pinning bypass
- Request/response logging

**Output:** Live traffic flows, captured tokens, runtime findings

**Files:**
- `backend/dynamic_analyzer/proxy_manager.py`
- `backend/dynamic_analyzer/frida_manager.py`
- `backend/dynamic_analyzer/jwt_interceptor.py`
- `backend/dynamic_analyzer/traffic_capture.py`
- `backend/dynamic_analyzer/setup_manager.py`

---

### 3. Correlation Agent

**Responsibility:** Cross-reference static and dynamic findings

**Triggers:**
- `/api/analyze/correlate` endpoint
- Post-analysis aggregation

**Capabilities:**
- Finding deduplication
- Static-dynamic correlation
- ML-based anomaly detection
- Risk score calculation
- CVSS scoring

**Output:** Correlated findings, risk score (0-150), priority ranking

**Files:**
- `backend/correlation_engine/correlator.py`
- `backend/correlation_engine/ml_analyzer.py`
- `backend/correlation_engine/risk_scorer.py`
- `backend/correlation_engine/cvss_scorer.py`
- `backend/correlation_engine/token_analyzer.py`
- `backend/correlation_engine/token_lifetime_analyzer.py`
- `backend/correlation_engine/ai_recommender.py`

---

### 4. Token Security Agent

**Responsibility:** Analyze token security (JWT, session tokens)

**Triggers:**
- Token detection in traffic
- `/api/analyze/token/*` endpoints

**Capabilities:**
- JWT structure validation
- Token lifetime analysis
- Token rotation detection
- Refresh token security
- Secret cracking
- Signature bypass testing

**Output:** Token analysis report, security recommendations

**Files:**
- `backend/correlation_engine/token_analyzer.py`
- `backend/correlation_engine/token_lifetime_analyzer.py`
- `backend/active_validator/jwt_attacker.py`
- `backend/active_validator/token_replayer.py`
- `backend/active_validator/token_rotation_tester.py`

---

### 5. Session Security Agent

**Responsibility:** Test session management security

**Triggers:**
- `/api/attack/session/*` endpoints
- Session lifecycle events

**Capabilities:**
- Session fixation testing
- Session timeout validation
- Concurrent session detection
- Logout invalidation verification
- Session storage analysis

**Output:** Session vulnerability report, exploitation evidence

**Files:**
- `backend/active_validator/session_tester.py`
- `backend/active_validator/lifecycle_tester.py`
- `backend/active_validator/session_validator.py`
- `backend/active_validator/bruteforce_tester.py`

---

### 6. Attack Chain Agent

**Responsibility:** Execute multi-step exploit chains

**Triggers:**
- `/api/attack/chain` endpoint
- Critical vulnerability confirmation

**Capabilities:**
- JWT bypass + data exfiltration chain
- Session fixation + account takeover chain
- Token replay + unauthorized access chain
- Bruteforce + account compromise chain

**Output:** Exploit chain results, proof of concept evidence

**Files:**
- `backend/active_validator/attack_chain.py`
- `backend/active_validator/bruteforce_tester.py`

---

### 7. MASVS Compliance Agent

**Responsibility:** Generate MASVS compliance checklists and acceptance criteria

**Triggers:**
- Analysis completion
- Manual compliance check request via `/api/masvs/*`

**Capabilities:**
- Auth type detection (JWT/OAuth2/Session)
- Dynamic checklist generation
- MASVS requirement mapping
- Acceptance criteria generation
- Compliance scoring
- Export Markdown/JSON

**Output:** MASVS checklist, compliance score, acceptance criteria

**Files:**
- `backend/masvs/masvs_database.py` - Complete MASVS v2.0 database
- `backend/masvs/auth_type_detector.py` - Auth type detection
- `backend/masvs/checklist_generator.py` - Checklist generation
- `backend/masvs/acceptance_criteria.py` - Acceptance criteria generator

**API Endpoints:**
- `/api/masvs/generate-checklist` - Generate checklist
- `/api/masvs/detect-auth-type` - Detect authentication type
- `/api/masvs/acceptance-criteria` - Generate acceptance criteria
- `/api/masvs/checklist/export` - Export checklist (Markdown/JSON)

---

### 8. Storage Security Agent

**Responsibility:** Analyze token and sensitive data storage security

**Triggers:**
- `/api/analyze/storage` endpoint
- Post-analysis storage audit

**Capabilities:**
- Insecure SharedPreferences detection
- Logcat leak detection
- Token-in-URL detection
- Analytics SDK data exfiltration detection
- Insecure file storage detection
- Secure storage usage verification (Keystore, EncryptedSharedPreferences)

**Output:** Storage security findings, secure storage score, recommendations

**Files:**
- `backend/static_analyzer/storage_scanner.py`

**API Endpoints:**
- `/api/analyze/storage` - Storage security analysis

---

### 9. Report Agent

**Responsibility:** Generate audit reports

**Triggers:**
- `/api/report/pdf` endpoint
- Analysis completion

**Capabilities:**
- PDF report generation
- Executive summary creation
- Technical findings documentation
- Remediation recommendations

**Output:** PDF audit report, JSON report data

**Files:**
- `backend/report_generator/pdf_generator.py`
- `backend/report_generator/pdf_builder.py`
- `backend/report_generator/evidence_collector.py`
- `backend/report_generator/llm_assistant.py`

---

## AI/LLM Integration

### Ollama Integration (Local LLM)
**Purpose:** Generate human-readable remediations and executive summaries

**Usage:**
```python
from correlation_engine.ai_recommender import AIRecommender
ai_recommender = AIRecommender()
remediations = ai_recommender.generate_remediations(findings)
```

**Endpoint:** `/api/llm/analyze`

### Gemini Integration (Cloud LLM)
**Purpose:** Alternative AI provider for remediation generation

**Configuration:**
```bash
export AI_PROVIDER="gemini"
export GEMINI_API_KEY="your-api-key"
```

---

## Agent Orchestration

### Analysis Workflow

```
1. User uploads APK
       ↓
2. StaticAnalyzerAgent → Static findings
       ↓
3. DynamicAnalyzerAgent → Traffic + tokens
       ↓
4. TokenSecurityAgent → Token analysis
5. SessionSecurityAgent → Session tests
6. StorageSecurityAgent → Storage analysis
       ↓
7. CorrelationAgent → Merge + score
       ↓
8. MASVSComplianceAgent → Checklist + Acceptance Criteria
       ↓
9. ReportAgent → PDF output
```

### Auto-Analysis on Startup

The system auto-starts agents on launch if a previous session exists:

```python
# backend/main.py - startup_event()
if session_state.get("package_name"):
    asyncio.create_task(trigger_auto_setup_internal())
```

---

## Agent Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UPLOAD_DIR` | `uploads/` | Temporary file storage |
| `JADX_PATH` | `tools/jadx/...` | JADX CLI location |
| `PROXY_PORT` | `8080` | MITM proxy port |
| `BACKEND_PORT` | `8001` | FastAPI port |
| `OLLAMA_URL` | `http://localhost:11434` | Local LLM endpoint |
| `AI_PROVIDER` | `ollama` | AI provider (ollama/gemini) |
| `TARGET_SERVER_PATH` | (auto-detect) | InsecureBank server path |

### Agent Timeouts

| Agent | Timeout |
|-------|---------|
| Static Analysis | 120s (JADX) |
| Dynamic Analysis | Persistent |
| Attack Tests | 30s per test |
| Report Generation | 60s |

---

## Agent State Management

Session state is persisted in `session_data.json`:

```json
{
  "package_name": "com.android.insecurebankv2",
  "last_apk": "app.apk",
  "static_findings": [...],
  "attack_results": [...],
  "timeline": [...],
  "logged_in_user": "admin",
  "masvs_checklist": {...},
  "storage_analysis": {...}
}
```

---

## Agent Safety Rules

1. **No External Actions:** Agents do not send emails, tweets, or external notifications
2. **Local-Only Exploits:** Attack chains target only localhost/emulator
3. **Recoverable Changes:** Use `trash` over `rm` for file operations
4. **No Private Data Exfiltration:** Findings stay local
5. **User Confirmation:** Require confirmation before destructive tests

---

## For Developers

### Adding a New Agent

1. Create module in appropriate package folder
2. Implement `analyze()`, `get_results()`, `reset()` methods
3. Register in `backend/main.py`
4. Add API endpoints
5. Update this AGENTS.md

### Agent Interface Template

```python
class BaseAgent:
    def __init__(self):
        self.results = []
        self.is_running = False

    def analyze(self, target) -> dict:
        raise NotImplementedError

    def get_results(self) -> list:
        return self.results

    def reset(self):
        self.results = []
```

---

## Related Documentation

- [STATUS.md](./STATUS.md) - Feature tracking
- [CLAUDE.md](./CLAUDE.md) - Development guidelines
- [README.md](./README.md) - Quick start guide
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues
