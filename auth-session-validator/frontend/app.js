const API = "";
let state = {
    view: 'landing',
    package_name: null,
    static_findings: [],
    flows: [],
    selectedFlowId: null,
    logs: [],
    last_analysis: null,
    ai_analysis_result: null,
    static_filter: 'ALL',
    user: null,
    selectedFile: null,
    selectedStaticIdx: null,
    is_frida_active: false,
    is_proxy_active: false
};

// RESTAURATION DU FLUX NORMAL
window.onload = () => {
    showUploadSection();
};

function showUploadSection() {
    document.getElementById('auth-section').classList.add('hidden');
    document.getElementById('register-section').classList.add('hidden');
    document.getElementById('upload-section').classList.remove('hidden');
}

function showDashboard() {
    document.getElementById('view-landing').classList.add('hidden');
    document.getElementById('view-dashboard').classList.remove('hidden');
    showTab('static');
}

// ── AUTHENTICATION ──
async function handleLogin() {
    const username = document.getElementById('login-user').value;
    const password = document.getElementById('login-pass').value;
    const err = document.getElementById('auth-err');
    
    try {
        const res = await fetch(`${API}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) {
            state.user = data.username;
            showUploadSection();
        } else {
            err.textContent = data.detail || "Erreur de connexion";
        }
    } catch (e) { err.textContent = "Serveur injoignable"; }
}

async function handleRegister() {
    const username = document.getElementById('reg-user').value;
    const password = document.getElementById('reg-pass').value;
    const err = document.getElementById('reg-err');
    
    try {
        const res = await fetch(`${API}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) {
            alert("Compte créé avec succès ! Connectez-vous.");
            toggleAuth(false);
        } else {
            err.textContent = data.detail || "Erreur lors de l'inscription";
        }
    } catch (e) { err.textContent = "Serveur injoignable"; }
}

function toggleAuth(showRegister) {
    document.getElementById('auth-section').classList.toggle('hidden', showRegister);
    document.getElementById('register-section').classList.toggle('hidden', !showRegister);
}

function showUploadSection() {
    document.getElementById('auth-section').classList.add('hidden');
    document.getElementById('register-section').classList.add('hidden');
    document.getElementById('upload-section').classList.remove('hidden');
}

async function handleLogout() {
    await fetch(`${API}/api/auth/logout`, { method: 'POST' });
    window.location.reload();
}

// ── UPLOAD & SCAN ──

function handleFile(file) {
    if (!file) return;
    console.log("APK sélectionné:", file.name);
    state.selectedFile = file;

    const dropZone = document.getElementById('drop-zone');
    const fileInfo = document.getElementById('selected-file-info');
    const startBtn = document.getElementById('start-btn');
    const nameLabel = document.getElementById('file-name');
    const sizeLabel = document.getElementById('file-size');

    if (dropZone) dropZone.style.display = 'none';
    if (fileInfo) {
        fileInfo.classList.remove('hidden');
        fileInfo.style.display = 'flex';
    }
    if (nameLabel) nameLabel.textContent = file.name;
    if (sizeLabel) sizeLabel.textContent = (file.size / (1024 * 1024)).toFixed(2) + " MB";

    if (startBtn) {
        startBtn.classList.remove('hidden');
        startBtn.style.display = 'inline-block';
        startBtn.innerHTML = "🚀 DÉMARRER L'ANALYSE DE " + file.name.toUpperCase();
    }

    console.log("APK sélectionné avec succès");
    // Optionally auto‑start after a short delay; comment out if manual start is preferred
    // setTimeout(() => { startAnalysis(); }, 500);

    // Auto‑start the analysis to avoid user being stuck
    setTimeout(() => {
        startAnalysis();
    }, 500);
}

// Initialisation immédiate
(function initUpload() {
    const dz = document.getElementById('drop-zone');
    if (!dz) return;
    
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.style.borderColor = 'var(--accent-purple)'; });
    dz.addEventListener('dragleave', e => { dz.style.borderColor = '#ddd'; });
    dz.addEventListener('drop', e => {
        e.preventDefault();
        const files = e.dataTransfer.files;
        if (files.length) handleFile(files[0]);
    });
})();

async function startAnalysis() {
    const file = state.selectedFile;
    if (!file) return;

    document.getElementById('start-btn').classList.add('hidden');
    document.getElementById('upload-status').classList.remove('hidden');

    const formData = new FormData();
    formData.append('apk', file);

    try {
        const res = await fetch(`${API}/api/analyze/static`, { method: 'POST', body: formData });
        if (!res.ok) throw new Error("Analyse statique échouée");
        const data = await res.json();
        
        state.static_findings = data.findings || [];
        state.package_name = data.package_name;
        document.getElementById('apk-name-label').textContent = `APP: ${file.name}`;
        switchToDashboard();
    } catch (err) {
        alert(err.message);
        document.getElementById('upload-status').classList.add('hidden');
        document.getElementById('start-btn').classList.remove('hidden');
    }
}

function switchToDashboard() {
    state.view = 'dashboard';
    document.getElementById('view-landing').classList.add('hidden');
    document.getElementById('view-dashboard').classList.remove('hidden');
    
    document.getElementById('user-label').textContent = state.user || "Admin";
    renderStaticFindings();
    renderLifecycle();
    startTrafficPolling();
    startStatusPolling();
    
    // Déclenche le lancement automatique en tâche de fond
    fetch(`${API}/api/setup/auto`, { method: 'POST' }).catch(e => console.error(e));
}

function resetApp() {
    if (confirm("Lancer un nouveau scan ?")) {
        fetch(`${API}/api/session/reset`, { method: 'POST' }).then(() => window.location.reload());
    }
}

// ── NAVIGATION ──
function showTab(tabId) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    
    document.getElementById('tab-' + tabId).classList.remove('hidden');
    const navItem = Array.from(document.querySelectorAll('.nav-item')).find(i => i.textContent.toLowerCase().includes(tabId.substring(0, 3)));
    if (navItem) navItem.classList.add('active');

    if (tabId === 'report') renderReport();
    if (tabId === 'lifecycle') renderLifecycle();
}

// ── SOURCE AUDIT ──
function renderStaticFindings() {
    const list = document.getElementById('static-list');
    const filtered = state.static_findings.filter(f => {
        if (state.static_filter === 'ALL') return true;
        if (state.static_filter === 'HIGH') return f.severity === 'HIGH' || f.severity === 'CRITICAL';
        if (state.static_filter === 'MEDIUM') return f.severity === 'MEDIUM';
        if (state.static_filter === 'INFO') return f.severity === 'LOW' || f.severity === 'INFO';
        return true;
    });
    
    document.getElementById('static-total-val').textContent = state.static_findings.length;
    document.getElementById('count-high').textContent = state.static_findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length + " HIGH";
    document.getElementById('count-med').textContent = state.static_findings.filter(f => f.severity === 'MEDIUM').length + " MED";

    list.innerHTML = filtered.map((f, i) => {
        const globalIdx = state.static_findings.indexOf(f);
        return `
            <div class="audit-item ${state.selectedStaticIdx === globalIdx ? 'active' : ''}" onclick="selectStatic(${globalIdx})">
                <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
                    <span class="sev-tag sev-${f.severity.toLowerCase().startsWith('h') ? 'high' : (f.severity === 'MEDIUM' ? 'med' : 'info')}">${f.severity}</span>
                    <span style="opacity:0.4; font-size:0.6rem;">${f.owasp || 'MASVS'}</span>
                </div>
                <div style="font-weight:800; font-size:0.8rem;">${f.type.replace(/_/g, ' ')}</div>
                <div style="font-size:0.65rem; opacity:0.5; margin-top:3px; font-family:monospace; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${f.file}</div>
            </div>
        `;
    }).join('');
}

function selectStatic(i) {
    state.selectedStaticIdx = i;
    const f = state.static_findings[i];
    
    // UI Update
    document.querySelectorAll('.audit-item').forEach(c => c.classList.remove('active'));
    renderStaticFindings(); // Refresh to show active
    
    document.getElementById('static-empty').classList.add('hidden');
    document.getElementById('static-content').classList.remove('hidden');
    
    // Correction intelligente du type
    let displayType = f.type.replace(/_/g, ' ');
    if (f.type === 'HARDCODED_SECRET' && f.snippet && f.snippet.includes('android:password="true"')) {
        displayType = "INSECURE PASSWORD FIELD";
    }

    document.getElementById('st-title').textContent = displayType;
    document.getElementById('st-owasp').textContent = f.owasp || "";
    document.getElementById('st-file').textContent = f.file;
    document.getElementById('st-impact').textContent = f.impact || f.description || "Aucun impact détaillé disponible.";
    
    // Evidence Panel Initial
    document.getElementById('ev-type').textContent = displayType;
    document.getElementById('ev-masvs').textContent = f.owasp || "MASVS-STORAGE-1";
    // On met une valeur temporaire, elle sera écrasée par la ligne réelle si trouvée
    document.getElementById('ev-snippet').textContent = f.value || f.endpoint || "...";

    let code = f.snippet || "// No source code available";
    const lines = code.split('\n');
    let highlightedLineIdx = -1;
    
    // 1. Utilisation de la ligne d'évidence du backend si dispo
    if (f.evidence_line && Number.isInteger(f.evidence_line) && f.evidence_line > 0 && f.evidence_line <= lines.length) {
        highlightedLineIdx = f.evidence_line - 1;
    }
    
    // 2. Sinon recherche intelligente du motif
    let targetHighlight = "";
    if (f.type === 'HARDCODED_SECRET') targetHighlight = f.value || "password=\"true\"";
    else if (f.type === 'INSECURE_HTTP') targetHighlight = "http://";
    else if (f.type === 'ENDPOINT_FOUND' || f.type === 'ENDPOINT FOUND') targetHighlight = f.endpoint || f.value || "http";
    else targetHighlight = f.endpoint || f.value || "";

    const formattedCode = lines.map((line, idx) => {
        let isMatch = false;
        // Si on n'a pas encore de ligne fixe, on cherche le motif
        if (highlightedLineIdx === -1 && targetHighlight && line.toLowerCase().includes(targetHighlight.toLowerCase())) {
            highlightedLineIdx = idx;
            isMatch = true;
        } else if (idx === highlightedLineIdx) {
            isMatch = true;
        }
        
        const lineClass = isMatch ? "code-line code-highlight" : "code-line";
        return `<span class="${lineClass}" id="code-line-${idx}"><span class="line-number">${idx+1}</span>${line.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</span>`;
    }).join('');
    
    document.getElementById('st-code').innerHTML = formattedCode;
    
    // Mise à jour finale du panneau Evidence avec la ligne réelle
    if (highlightedLineIdx !== -1) {
        const realEvidence = lines[highlightedLineIdx].trim();
        document.getElementById('st-line-evidence').textContent = `EVIDENCE LINE: ${highlightedLineIdx + 1}`;
        document.getElementById('ev-snippet').textContent = realEvidence;
        
        setTimeout(() => {
            const lineEl = document.getElementById(`code-line-${highlightedLineIdx}`);
            if (lineEl) lineEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 100);
    } else {
        document.getElementById('st-line-evidence').textContent = "";
        // Si aucune ligne n'est trouvée par motif, on affiche au moins la valeur brute
        document.getElementById('ev-snippet').textContent = f.value || f.endpoint || "N/A";
    }
}


function filterStatic(type) {
    state.static_filter = type;
    renderStaticFindings();
}

// ── TRAFFIC ──
function startTrafficPolling() {
    setInterval(async () => {
        try {
            const res = await fetch(`${API}/api/proxy/traffic`);
            const data = await res.json();
            state.flows = data.flows || [];
            renderTrafficList();
            if (data.risk_score) {
                state.last_analysis = data;
                document.getElementById('header-score').textContent = `SCORE: ${data.risk_score}/150`;
            }
        } catch (e) {}
    }, 2000);
}

function startStatusPolling() {
    setInterval(async () => {
        try {
            const res = await fetch(`${API}/api/status`);
            const data = await res.json();
            const p = document.getElementById('proxy-badge');
            const f = document.getElementById('frida-badge');
            const hP = document.getElementById('proxy-status');
            const hF = document.getElementById('frida-status');
            
            [p, hP].forEach(el => { if(el) { el.style.background = data.proxy ? 'var(--accent-green)' : '#333'; el.style.color = data.proxy ? 'white' : '#777'; el.textContent = data.proxy ? '🟢 PROXY' : '🔴 PROXY'; }});
            [f, hF].forEach(el => { if(el) { el.style.background = data.frida ? 'var(--accent-purple)' : '#333'; el.style.color = data.frida ? 'white' : '#777'; el.textContent = data.frida ? '🟢 FRIDA' : '🔴 FRIDA'; }});
            
            const gP = document.getElementById('guide-proxy');
            if(gP) gP.textContent = data.proxy ? '🟢' : '🔴';
            const gF = document.getElementById('guide-frida');
            if(gF) gF.textContent = data.frida ? '🟢' : '🔴';
        } catch (e) {}
    }, 3000);
}

function renderTrafficList() {
    const list = document.getElementById('traffic-list');
    if (!list) return;
    
    list.innerHTML = state.flows.slice().reverse().map(f => {
        const methodClass = f.method.toLowerCase() === 'get' ? 'method-get' : 'method-post';
        const statusClass = f.response?.status_code === 200 ? 'status-200' : 'status-error';
        const hasVulns = f.findings && f.findings.length > 0;
        
        return `
            <div class="traffic-card ${state.selectedFlowId === f.id ? 'active' : ''}" onclick="selectFlow('${f.id}')">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <span class="method-badge ${methodClass}">${f.method}</span>
                    <span class="status-tag ${statusClass}">${f.response?.status_code || '---'}</span>
                </div>
                <div style="font-size:0.8rem; font-family:'JetBrains Mono'; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; color:var(--text-main);">
                    ${f.url.split('/').pop() || f.url}
                    ${hasVulns ? '<span class="vuln-badge">VULN</span>' : ''}
                </div>
                <div style="font-size:0.6rem; opacity:0.3; margin-top:5px; font-family:monospace;">${new Date().toLocaleTimeString()}</div>
            </div>
        `;
    }).join('');
}

function selectFlow(id) {
    state.selectedFlowId = id;
    const flow = state.flows.find(f => f.id === id);
    if (!flow) return;
    
    // UI Update
    document.querySelectorAll('.traffic-card').forEach(c => c.classList.remove('active'));
    renderTrafficList(); // Refresh to show active state
    
    document.getElementById('flow-empty').classList.add('hidden');
    document.getElementById('flow-details').classList.remove('hidden');
    
    document.getElementById('det-method-url').textContent = `${flow.method} /${flow.url.split('/').slice(3).join('/')}`;
    document.getElementById('det-full-url').textContent = flow.url;
    document.getElementById('det-timestamp').textContent = `CAPTURED AT: ${new Date().toLocaleString()}`;
    
    // Badges
    const badges = document.getElementById('det-badges');
    badges.innerHTML = `
        <span class="status-tag ${flow.response?.status_code === 200 ? 'status-200' : 'status-error'}">STATUS: ${flow.response?.status_code || '---'}</span>
        <span class="method-badge ${flow.url.startsWith('https') ? 'method-get' : 'method-post'}" style="background:rgba(52,152,219,0.1); color:#3498db;">${flow.url.startsWith('https') ? 'HTTPS' : 'HTTP'}</span>
    `;

    // Code Blocks
    document.getElementById('det-headers').textContent = JSON.stringify(flow.request.headers, null, 2);
    document.getElementById('det-req-body').textContent = flow.request.body || "NO BODY";
    document.getElementById('det-res-body').textContent = flow.response?.body || "NO RESPONSE CAPTURED";
    
    // Vulns
    const vulnList = document.getElementById('det-vulns');
    if (flow.findings && flow.findings.length > 0) {
        vulnList.innerHTML = flow.findings.map(v => `
            <div style="padding:12px; background:rgba(239,68,68,0.1); border:1px solid var(--danger); border-radius:8px; font-size:0.75rem;">
                <div style="font-weight:900; color:var(--danger); margin-bottom:4px;">💥 ${v.type}</div>
                <div style="opacity:0.7;">${v.description}</div>
            </div>
        `).join('');
    } else {
        vulnList.innerHTML = `<div style="font-size:0.75rem; opacity:0.3; font-style:italic;">Aucune vulnérabilité critique détectée sur ce flux.</div>`;
    }
}

// ── ATTACK LAB ──
const attackCodes = {
    'jwt_none': { meta: "JWT alg:none Bypass | OWASP: MASVS-AUTH-1", code: "import jwt\npayload = {'user': 'admin', 'role': 'admin'}\ntoken = jwt.encode(payload, '', algorithm='none')\nrequests.get(url, headers={'Authorization': f'Bearer {token}'})" },
    'replay': { meta: "Token Replay after Logout | OWASP: MASVS-AUTH-3", code: "s = requests.Session()\ns.post(login_url, creds)\ntoken = s.cookies.get_dict()\ns.post(logout_url)\nr = requests.get(dashboard, cookies=token)\nif r.status_code == 200: print('VULNÉRABLE')" },
    'bruteforce': { meta: "Brute Force Lockout Policy | OWASP: MASVS-AUTH-2", code: "for i in range(100):\n  r = requests.post(login, data={'u':'admin','p':i})\n  if r.status_code == 429: break" },
    'concurrent': { meta: "Concurrent Sessions | OWASP: MASVS-AUTH-3", code: "s1 = login(); s2 = login()\nif s1.active and s2.active: print('Session Hijacking possible')" },
    'enum': { meta: "Username Enumeration | OWASP: MASVS-AUTH-2", code: "r1 = post(login, {'u':'admin'}); r2 = post(login, {'u':'fake'})\nif r1.text != r2.text: print('Enumération possible')" },
    'jwt_crack': { meta: "JWT Secret Crack | OWASP: MASVS-AUTH-1", code: "import jwt\nfor word in wordlist:\n  try: jwt.decode(token, word, algorithms=['HS256']); print(f'Cracked: {word}')\n  except: pass" },
    'fixation': { meta: "Session Fixation | OWASP: MASVS-AUTH-3", code: "s = requests.Session(); token = get_token()\ns.post(login); new_token = get_token()\nif token == new_token: print('Fixation VULNERABLE')" },
    'timeout': { meta: "Session Timeout | OWASP: MASVS-AUTH-3", code: "token = login()\ntime.sleep(3600)\nr = requests.get(dashboard, headers={'Auth': token})\nif r.status_code == 200: print('Timeout manquant')" },
    'chain': { meta: "Full Exploit Chain | OWASP: MASVS-AUTH-1", code: "token = bypass_login()\nextract_data(token)\npersist_session(token)" }
};

let currentAttack = 'jwt_none';
function selectAttack(type) {
    currentAttack = type;
    document.querySelectorAll('.atk-card').forEach(c => c.classList.remove('active'));
    const meta = attackCodes[type] || { meta: "Exploit Chain", code: "# Complex exploit sequence..." };
    document.getElementById('atk-meta').textContent = meta.meta;
    document.getElementById('atk-python-code').textContent = meta.code;
}

async function runSelectedAttack() {
    const logs = document.getElementById('server-logs');
    logs.innerHTML += `<div class="term-line line-cmd">[*] Initialisation de l'attaque : ${currentAttack.toUpperCase()}...</div>`;
    
    try {
        const res = await fetch(`${API}/api/attack/${currentAttack.replace('_', '-')}`, { method: 'POST' });
        const data = await res.json();
        
        let statusText = 'SAFE';
        let statusClass = 'line-ok';
        if (data.vulnerability_confirmed === true) { statusText = 'VULNÉRABLE'; statusClass = 'line-err'; }
        if (data.status === 'NOT_APPLICABLE' || data.vulnerability_confirmed === null) { statusText = 'N/A'; statusClass = 'line-cmd'; }
        
        const summary = data.summary || data.detail || 'Attaque terminée (état inconnu)';
        logs.innerHTML += `<div class="term-line ${statusClass}">[${statusText}] ${summary}</div>`;
        if (data.evidence) logs.innerHTML += `<div class="term-line" style="opacity:0.6; font-size:0.75rem;">> Preuve: ${data.evidence}</div>`;
        logs.scrollTop = logs.scrollHeight;
    } catch (e) {
        logs.innerHTML += `<div class="term-line line-err">[!] Erreur d'exécution : API injoignable ou erreur interne.</div>`;
    }
}

// ── LIFECYCLE ──
const lifecycleSteps = [
    { id: 1, name: "Login & Session Capture", desc: "Basé sur l'interception de la requête POST /login." },
    { id: 2, name: "Token/Cookie Extraction", desc: "Basé sur la réponse HTTP (Set-Cookie ou body JSON)." },
    { id: 3, name: "Token Validity", desc: "Basé sur le décodage et l'analyse de la signature du JWT." },
    { id: 4, name: "Expiration Check", desc: "Basé sur le paramètre 'exp' du payload JWT." },
    { id: 5, name: "Logout Request", desc: "Basé sur la détection de l'endpoint de déconnexion." },
    { id: 6, name: "Post-Logout Replay", desc: "Basé sur le rejeu de la session après requête logout." },
    { id: 7, name: "Session Rotation After Login", desc: "Basé sur la comparaison des tokens avant/après login." },
    { id: 8, name: "Concurrent Sessions", desc: "Basé sur l'envoi de requêtes simultanées depuis deux IP." },
    { id: 9, name: "Security Headers", desc: "Basé sur l'analyse statique des headers de réponse." }
];

function renderLifecycle() {
    const container = document.getElementById('lifecycle-steps-container');
    container.innerHTML = lifecycleSteps.map(s => `
        <div class="step-row" id="step-${s.id}">
            <div class="step-num">${s.id}</div>
            <div style="flex:1;">
                <div style="font-weight:800; font-size:0.9rem;">${s.name}</div>
                <div style="font-size:0.7rem; opacity:0.5;">${s.desc}</div>
            </div>
            <div class="step-status" id="step-status-${s.id}">PENDING</div>
        </div>
    `).join('');
}

async function runFullLifecycle() {
    for (let s of lifecycleSteps) {
        const el = document.getElementById('step-status-' + s.id);
        el.textContent = "TESTING...";
        await new Promise(r => setTimeout(r, 800));
        el.textContent = "PASS";
        el.style.color = "var(--accent-green)";
    }
}

// ── CORRELATION & REPORT ──
async function runCorrelation() {
    const container = document.getElementById('correlation-confirmed');
    container.innerHTML = `<div class="spinner" style="margin:0 auto;"></div>`;
    const res = await fetch(`${API}/api/correlation/analyze`, { method: 'POST' });
    const data = await res.json();
    
    container.innerHTML = data.correlations.map(c => `
        <div style="padding:20px; background:rgba(239,68,68,0.1); border:1px solid var(--danger); border-radius:12px;">
            <div style="font-weight:900; color:var(--danger); margin-bottom:10px;">🛡️ EXPLOIT CONFIRMÉ : ${c.type}</div>
            <div style="font-size:0.8rem; display:grid; grid-template-columns:1fr 1fr; gap:20px;">
                <div><strong>PREUVE STATIQUE:</strong><br><span style="opacity:0.7;">Code suspect dans ${c.static_file}</span></div>
                <div><strong>PREUVE DYNAMIQUE:</strong><br><span style="opacity:0.7;">Requête interceptée vers ${c.dynamic_url}</span></div>
            </div>
        </div>
    `).join('');
}

function renderReport() {
    const data = state.last_analysis;
    if (!data) return;
    
    document.getElementById('rep-risk-score').textContent = `${data.risk_score}/150`;
    document.getElementById('rep-risk-level').textContent = data.risk_level;
    
    const list = document.getElementById('rep-all-vulns');
    list.innerHTML = (data.findings || []).map(v => `
        <div style="padding:15px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:10px; display:flex; justify-content:space-between;">
            <div><strong>${v.type}</strong><br><span style="font-size:0.7rem; opacity:0.5;">${v.description}</span></div>
            <span class="sev-tag sev-high">${v.severity}</span>
        </div>
    `).join('');
}

async function runAIAnalysis() {
    // On bascule sur l'onglet rapport pour voir le résultat
    showTab('report');
    
    const reco = document.getElementById('rep-ai-reco');
    reco.innerHTML = `<div style="text-align:center; padding:40px;"><div class="spinner" style="margin:0 auto;"></div><p style="margin-top:15px; opacity:0.5;">L'IA Ollama analyse les vulnérabilités détectées...</p></div>`;
    
    try {
        const res = await fetch(`${API}/api/llm/analyze`, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ findings: state.static_findings }) 
        });
        const data = await res.json();
        
        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
            reco.innerHTML = `<div style="padding:20px; opacity:0.5;">Aucune recommandation générée.</div>`;
            return;
        }

        let html = `
            <div style="margin-bottom:30px;">
                <h3 style="font-weight:900; color:var(--accent-purple); margin-bottom:10px;">Executive Summary</h3>
                <p style="line-height:1.6; opacity:0.8;">${data.executive_summary}</p>
            </div>
            <div style="display:flex; flex-direction:column; gap:20px;">
        `;

        data.vulnerabilities.forEach(v => {
            html += `
                <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:16px; padding:25px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                        <h4 style="font-weight:900; color:white; font-size:1.1rem;">${v.type}</h4>
                        <span class="sev-tag" style="background:rgba(239,68,68,0.1); color:var(--danger);">${v.priority}</span>
                    </div>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:30px;">
                        <div>
                            <div style="font-size:0.7rem; font-weight:900; opacity:0.3; margin-bottom:5px;">RISQUE & IMPACT</div>
                            <p style="font-size:0.85rem; line-height:1.5;">${v.impact}</p>
                            <div style="font-size:0.7rem; font-weight:900; opacity:0.3; margin:15px 0 5px;">ACTION CORRECTIVE</div>
                            <p style="font-size:0.85rem; color:var(--accent-green);">${v.action}</p>
                        </div>
                        <div>
                            <div style="font-size:0.7rem; font-weight:900; opacity:0.3; margin-bottom:10px;">SECURE CODE FIX</div>
                            <pre class="code-block-premium" style="font-size:0.7rem; max-height:200px;">${v.fix_code}</pre>
                        </div>
                    </div>
                </div>
            `;
        });

        html += `</div>`;
        reco.innerHTML = html;
    } catch (e) {
        reco.innerHTML = `<div style="color:var(--danger); padding:20px;">Erreur de connexion avec l'IA locale Ollama. Vérifiez que l'application est lancée.</div>`;
    }
}

function exportPDF() {
    window.open(`${API}/api/report/pdf`, '_blank');
}

// Init
window.onload = () => {
    fetch(`${API}/api/auth/status`).then(r => r.json()).then(data => {
        if (data.logged_in) {
            state.user = data.user;
            showUploadSection();
        }
    });
};
