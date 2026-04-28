# Troubleshooting Guide - Auth & Session Analyzer

This guide explains how to resolve common issues encountered during dynamic analysis with Android emulators, including network and Frida connection problems.

---

## Quick Start

### Check System Status

```bash
# Check backend is running
curl http://localhost:8001/api/status

# Check components
curl http://localhost:8001/api/status/components
```

### Required Components

| Component | Port | Status Check |
|-----------|------|--------------|
| Backend FastAPI | 8001 | `/api/status` |
| MITM Proxy | 8080 | `/api/proxy/status` |
| Frida Server | 27042 | `adb shell pgrep frida-server` |
| Test Server (InsecureBank) | 8888 | `curl http://localhost:8888` |

---

## 1. Network Connection Issues (Emulator Offline)

If the emulator cannot reach the server (even with `10.0.2.2`), use **ADB Reverse Tunnel**. This forces the emulator to use USB to reach services on your machine.

### Commands to Run:

```bash
# Redirect emulator traffic to your PC
adb reverse tcp:8888 tcp:8888  # For InsecureBank server
adb reverse tcp:8001 tcp:8001  # For backend
adb reverse tcp:8080 tcp:8080  # For MITM proxy
```

### Application Configuration:

Once the tunnel is active, use **127.0.0.1** instead of `10.0.2.2` in your Android app configuration.

---

## 2. Frida Issues (Instrumentation)

If Frida cannot attach or the dashboard remains empty.

### Check Frida Server on Device:

```bash
# Ensure root access
adb root

# Check if server is running
adb shell pgrep frida-server

# If not, restart it
adb shell "/data/local/tmp/frida-server &"
```

### Restart Analysis from Backend:

```bash
# Use curl to force restart
curl -X POST "http://localhost:8001/api/frida/start?package_name=com.android.insecurebankv2"
```

### Common Frida Problems:

| Problem | Solution |
|---------|----------|
| "Connection refused" | Run `adb root` first |
| "Unable to attach" | Kill existing frida-server: `adb shell "killall frida-server"` |
| Version mismatch | Update frida-tools: `pip install -U frida-tools` |
| Process not found | Use spawn mode via `/api/frida/spawn` endpoint |

---

## 3. Test Server (InsecureBankv2)

The Android app needs a server to validate login.

### Command:

```bash
cd path/to/Android-InsecureBankv2/AndroLabServer
python server_v3.py
```

*Note: Use `server_v3.py` for Python 3.*

### Auto-Start:

The backend automatically starts the test server when detecting `InsecureBankv2` APK. Configure via `TARGET_SERVER_PATH` environment variable if needed.

---

## 4. Proxy Configuration

For traffic to be intercepted:

1. **Android Proxy:** Set emulator proxy to `127.0.0.1:8080` (after `adb reverse`)
2. **Certificate:** For HTTPS testing, install the `mitm.it` certificate on the device

### Installing mitmproxy Certificate:

```bash
# 1. Start proxy
curl -X POST http://localhost:8001/api/proxy/start

# 2. On Android device/emulator:
# - Configure proxy: Settings > Wi-Fi > Long-press network > Modify > Proxy: Manual
# - Host: 127.0.0.1, Port: 8080

# 3. Open browser on device and visit:
http://mitm.it

# 4. Download and install the certificate
# - For Android 7+: Requires root or Magisk module
```

---

## 5. JWT Interception Issues

If JWT tokens are not being captured:

### Check Traffic Flow:

```bash
curl http://localhost:8001/api/proxy/traffic
```

### Verify Token Format:

- Tokens must be in `Authorization: Bearer <token>` header
- Or in request/response body as JSON field

### Frida Fallback:

If proxy cannot capture HTTPS traffic (SSL pinning), Frida interceptor will capture tokens automatically.

---

## 6. Backend Path Errors

If you see hardcoded path errors:

### Fix:

Edit `backend/config.py`:

```python
TARGET_SERVER_PATH = os.getenv(
    "TARGET_SERVER_PATH",
    r"C:\Your\Path\To\Android-InsecureBankv2\AndroLabServer\server_v3.py"
)
```

Or set environment variable:

```bash
export TARGET_SERVER_PATH="/your/path/to/server_v3.py"
```

---

## 7. PDF Report Generation Fails

### Check Dependencies:

```bash
pip install reportlab
```

### Verify:

```bash
python -c "import reportlab; print(reportlab.__version__)"
```

---

## Token Security Analysis

### Token Lifetime Analyzer

| Problem | Solution |
|---------|----------|
| Token without `exp` claim | CRITICAL vulnerability - token never expires |
| Lifetime > 24h | HIGH vulnerability - reduce lifetime or use refresh tokens |
| Missing claims (iss, sub, aud) | LOW-MEDIUM vulnerabilities depending on claim |

### Token Rotation Tester

| Problem | Solution |
|---------|----------|
| Refresh token reusable | CRITICAL - implement one-time use rotation |
| Access token unchanged on refresh | MEDIUM - generate new access token each refresh |
| Race condition on refresh | HIGH - use transactional locks |

### Storage Scanner

| Problem | Solution |
|---------|----------|
| Unencrypted SharedPreferences | Use `EncryptedSharedPreferences` |
| Tokens in Logcat | Remove sensitive logs, use `BuildConfig.DEBUG` |
| Tokens in URLs | Use `Authorization: Bearer <token>` headers |
| No Keystore usage | Implement `Android Keystore` for cryptographic keys |

---

## MASVS Compliance

### Generate Checklist

```bash
# Detect authentication type
curl -X POST http://localhost:8001/api/masvs/detect-auth-type

# Generate checklist
curl -X POST http://localhost:8001/api/masvs/generate-checklist

# Export to Markdown
curl http://localhost:8001/api/masvs/checklist/export?format=markdown
```

### Acceptance Criteria

```bash
# Generate for a user story
curl -X POST "http://localhost:8001/api/masvs/acceptance-criteria?user_story=Login+with+JWT"
```

---

## Dashboard Issues

### Right Panel Not Showing

If the right panel doesn't display when clicking a flow:

1. **Refresh the page (F5)**
2. Check browser console for JavaScript errors
3. Verify backend is returning traffic data

### Traffic Not Updating

1. Check proxy status: `curl http://localhost:8001/api/proxy/status`
2. Restart proxy: `curl -X POST http://localhost:8001/api/proxy/start`
3. Check Android proxy configuration

---

## Default Credentials (InsecureBank)

Username: `admin`
Password: `admin@123`

---

## Log Collection

### Get Server Logs:

```bash
curl http://localhost:8001/api/logs/server
```

### Get Backend Logs:

Check console output where `python backend/main.py` is running.

---

## Session Reset

If session state becomes corrupted:

```bash
curl -X POST http://localhost:8001/api/session/reset
```

This clears all findings and resets to default state.
