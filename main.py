import hashlib
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(title="CanaryDocs Gateway")

USERS = {
    "token_alice": {"id": "USR-101", "name": "Alice", "role": "Employee", "clearance": 1},
    "token_bob": {"id": "USR-102", "name": "Bob (Manager)", "role": "Manager", "clearance": 2},
    "token_eve": {"id": "USR-999", "name": "Eve (Contractor)", "role": "Contractor", "clearance": 0},
}

DOCS = {
    "DOC-001": {
        "id": "DOC-001",
        "title": "Public Policy Guidelines.txt",
        "clearance": 0,
        "is_trap": False,
        "category": "Compliance",
        "size": "14.2 KB",
        "body": "Zero-trust access policy guidelines.\n\n1. All outbound documents are dynamically fingerprinted with cryptographic canary hashes.\n2. Standard contractors (L0) are restricted to public compliance baselines.\n3. Unauthorized access attempts to elevated assets are automatically logged to the immutable SOC ledger."
    },
    "DOC-002": {
        "id": "DOC-002",
        "title": "Internal Engineering Roadmap.txt",
        "clearance": 1,
        "is_trap": False,
        "category": "Engineering",
        "size": "48.7 KB",
        "body": "Q4 Gateway migration targets.\n\n- Phase 1: Enforce strict RBAC policy checks on edge document endpoints.\n- Phase 2: Embed deterministic SHA-256 attribution tokens per download session.\n- Phase 3: Deploy active honeytoken tripwires across high-value storage buckets."
    },
    "DOC-003": {
        "id": "DOC-003",
        "title": "Executive Financial Audit.txt",
        "clearance": 2,
        "is_trap": False,
        "category": "Executive Finance",
        "size": "112.4 KB",
        "body": "Restricted executive financial ledger.\n\nCONFIDENTIAL SUMMARY:\n- Q3 Gross Margin: 74.8% (+3.2% YoY)\n- Security Infrastructure Allocation: $1.45M\n- Pending M&A Due Diligence Reserve: $8.20M\n\nWARNING: Redistribution outside L2 Managerial clearance is strictly prohibited."
    },
    "DOC-HONEY": {
        "id": "DOC-HONEY",
        "title": "Q3_Salaries_Unencrypted.xlsx",
        "clearance": 99,
        "is_trap": True,
        "category": "Decoy / Honeytoken",
        "size": "2.1 MB",
        "body": "HONEYTOKEN_TRIPWIRE"
    },
}

LOGS = []
FINGERPRINTS = {}

def log_event(event, uid, did, status, detail):
    LOGS.insert(0, {
        "time": datetime.utcnow().strftime("%H:%M:%S UTC"),
        "event": event,
        "user": uid,
        "doc": did,
        "status": status,
        "detail": detail
    })

def auth_user(authorization: Optional[str] = Header(None)):
    if not authorization or authorization not in USERS:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    return USERS[authorization]

@app.get("/api/documents")
def get_documents(authorization: Optional[str] = Header(None)):
    u = auth_user(authorization)
    return {
        "user": u["name"],
        "user_id": u["id"],
        "role": u["role"],
        "clearance": u["clearance"],
        "docs": [
            {
                "id": d["id"],
                "title": d["title"],
                "clearance": d["clearance"],
                "is_trap": d["is_trap"],
                "category": d.get("category", "General"),
                "size": d.get("size", "10 KB"),
                "accessible": (d["clearance"] <= u["clearance"]) and (not d["is_trap"])
            }
            for d in DOCS.values() if d["clearance"] <= u["clearance"] or d["is_trap"]
        ],
        "all_docs": [
            {
                "id": d["id"],
                "title": d["title"],
                "clearance": d["clearance"],
                "is_trap": d["is_trap"],
                "category": d.get("category", "General"),
                "size": d.get("size", "10 KB"),
                "accessible": (d["clearance"] <= u["clearance"]) and (not d["is_trap"])
            }
            for d in DOCS.values()
        ]
    }

@app.get("/api/documents/{doc_id}/download")
@app.get("/api/download/{doc_id}")
def download_doc(doc_id: str, authorization: Optional[str] = Header(None)):
    u = auth_user(authorization)
    doc = DOCS.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")
    if doc["is_trap"]:
        log_event("HONEYTOKEN_BREACH", u["id"], doc_id, 403, f"{u['name']} triggered canary bait!")
        raise HTTPException(status_code=403, detail="Access Denied: Security violation detected and logged to the incident response team.")
    if u["clearance"] < doc["clearance"]:
        log_event("UNAUTHORIZED_ATTEMPT", u["id"], doc_id, 403, f"Clearance L{u['clearance']} insufficient for L{doc['clearance']}.")
        raise HTTPException(status_code=403, detail="Forbidden: Your clearance tier is insufficient for this asset.")
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    fp = hashlib.sha256(f"{u['id']}:{doc_id}:{ts}".encode()).hexdigest()[:12]
    FINGERPRINTS[fp] = {
        "fingerprint": fp,
        "user_id": u["id"],
        "user_name": u["name"],
        "role": u["role"],
        "clearance": u["clearance"],
        "doc_id": doc_id,
        "doc_title": doc["title"],
        "timestamp": ts
    }
    log_event("DOWNLOAD_OK", u["id"], doc_id, 200, f"Watermark fingerprint: {fp}")
    return PlainTextResponse(f"=== {doc['title']} ===\nISSUED TO: {u['name']} ({u['id']})\nTIMESTAMP: {ts}\nCANARY FINGERPRINT: [{fp}]\n\n{doc['body']}")

@app.get("/api/verify-canary")
def verify_canary(fp: str = Query(..., description="Canary fingerprint hash")):
    clean_fp = fp.strip().strip("[]").lower()
    record = FINGERPRINTS.get(clean_fp)
    if not record:
        raise HTTPException(status_code=404, detail="No active canary record matches this fingerprint hash.")
    return {"matched": True, "record": record}

@app.get("/api/telemetry")
def get_telemetry(authorization: Optional[str] = Header(None)):
    auth_user(authorization)
    total_events = len(LOGS)
    downloads = sum(1 for l in LOGS if l["event"] == "DOWNLOAD_OK")
    honeytokens = sum(1 for l in LOGS if l["event"] == "HONEYTOKEN_BREACH")
    unauthorized = sum(1 for l in LOGS if l["event"] in ("UNAUTHORIZED_ATTEMPT", "FORBIDDEN_AUDIT_VIEW"))
    return {
        "total_events": total_events,
        "downloads_issued": downloads,
        "active_fingerprints": len(FINGERPRINTS),
        "honeytoken_alerts": honeytokens,
        "blocked_attempts": unauthorized + honeytokens
    }

@app.get("/api/audit-logs")
def get_logs(authorization: Optional[str] = Header(None)):
    u = auth_user(authorization)
    if u["role"] != "Manager":
        log_event("FORBIDDEN_AUDIT_VIEW", u["id"], "LOGS", 403, "Non-manager attempted to view audit ledger.")
        raise HTTPException(status_code=403, detail="Forbidden: Audit logs are restricted to Managers.")
    return {"logs": LOGS}

@app.get("/", response_class=HTMLResponse)
def index():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CanaryDocs Gateway | Zero-Trust Document Guard & Honeytoken SOC</title>
<style>
  :root {
    --bg-base: #060b14;
    --bg-panel: #0f172a;
    --bg-card: #1e293b;
    --bg-card-hover: #263449;
    --border: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --accent-gold: #f59e0b;
    --accent-cyan: #06b6d4;
    --accent-emerald: #10b981;
    --accent-crimson: #f43f5e;
    --accent-purple: #8b5cf6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: radial-gradient(circle at top right, #111c35 0%, var(--bg-base) 65%);
    color: var(--text-main);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    min-height: 100vh;
    padding: 1.5rem 2rem;
    line-height: 1.5;
  }
  .container { max-width: 1280px; margin: 0 auto; }

  /* Top Header */
  .topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.5rem;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 1.25rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.4);
  }
  .brand { display: flex; align-items: center; gap: 0.9rem; }
  .brand-icon {
    width: 42px; height: 42px; border-radius: 10px;
    background: linear-gradient(135deg, #f59e0b, #ea580c);
    display: flex; align-items: center; justify-content: center;
    font-weight: 900; font-size: 1.2rem; color: #060b14;
    box-shadow: 0 0 18px rgba(245, 158, 11, 0.4);
  }
  .brand h1 { font-size: 1.35rem; font-weight: 800; letter-spacing: -0.02em; color: #fff; }
  .brand p { font-size: 0.78rem; color: var(--text-muted); }
  .status-pill {
    display: flex; align-items: center; gap: 0.5rem;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.35);
    color: #34d399;
    padding: 0.4rem 0.85rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #10b981;
    box-shadow: 0 0 8px #10b981;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(1.2); }
  }

  /* Telemetry Row */
  .telemetry-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.25rem;
  }
  .stat-card {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.9rem 1.2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .stat-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
  .stat-value { font-size: 1.6rem; font-weight: 800; margin-top: 0.15rem; }
  .stat-badge {
    font-size: 0.7rem; padding: 0.25rem 0.55rem; border-radius: 6px; font-weight: 700;
  }

  /* Persona Selector Bar */
  .persona-bar {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1rem 1.25rem;
    margin-bottom: 1.25rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
  }
  .persona-cards { display: flex; gap: 0.75rem; flex-wrap: wrap; }
  .persona-btn {
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-main);
    padding: 0.6rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.65rem;
    transition: all 0.18s ease;
    text-align: left;
  }
  .persona-btn:hover { background: var(--bg-card-hover); transform: translateY(-1px); }
  .persona-btn.active {
    border-color: var(--accent-gold);
    background: rgba(245, 158, 11, 0.12);
    box-shadow: 0 0 15px rgba(245, 158, 11, 0.18);
  }
  .avatar {
    width: 32px; height: 32px; border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 0.85rem;
  }
  .p-name { font-size: 0.85rem; font-weight: 700; display: block; }
  .p-role { font-size: 0.7rem; color: var(--text-muted); display: block; }

  /* Main Workspace Grid */
  .workspace {
    display: grid;
    grid-template-columns: 1.05fr 1.25fr;
    gap: 1.25rem;
    margin-bottom: 1.25rem;
  }
  .panel {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
  }
  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid rgba(51, 65, 85, 0.6);
  }
  .panel-title { font-size: 0.95rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
  .panel-sub { font-size: 0.75rem; color: var(--text-muted); }

  /* Document Cards */
  .doc-list { display: flex; flex-direction: column; gap: 0.7rem; }
  .doc-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 0.85rem 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: all 0.15s ease;
  }
  .doc-card:hover { border-color: #475569; background: var(--bg-card-hover); }
  .doc-card.trap-card {
    border-color: rgba(244, 63, 94, 0.4);
    background: linear-gradient(90deg, rgba(244, 63, 94, 0.08), rgba(30, 41, 59, 0.95));
  }
  .doc-info { display: flex; flex-direction: column; gap: 0.25rem; }
  .doc-title-row { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .doc-title { font-weight: 700; font-size: 0.88rem; color: #fff; }
  .doc-meta { font-size: 0.72rem; color: var(--text-muted); }

  .tier-badge {
    font-size: 0.65rem;
    font-weight: 800;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    letter-spacing: 0.04em;
  }
  .tier-0 { background: rgba(16, 185, 129, 0.18); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
  .tier-1 { background: rgba(6, 182, 212, 0.18); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4); }
  .tier-2 { background: rgba(139, 92, 246, 0.2); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.45); }
  .tier-99 { background: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.5); }

  .req-btn {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: #060b14;
    border: none;
    padding: 0.5rem 0.95rem;
    border-radius: 6px;
    font-weight: 700;
    font-size: 0.78rem;
    cursor: pointer;
    transition: all 0.15s ease;
    white-space: nowrap;
  }
  .req-btn:hover { filter: brightness(1.1); transform: translateY(-1px); }
  .req-btn.locked-btn {
    background: rgba(51, 65, 85, 0.8);
    color: #cbd5e1;
    border: 1px solid #475569;
  }
  .req-btn.trap-btn {
    background: rgba(244, 63, 94, 0.2);
    color: #fda4af;
    border: 1px solid rgba(244, 63, 94, 0.5);
  }
  .req-btn.trap-btn:hover { background: rgba(244, 63, 94, 0.35); }

  /* Document Output Terminal & Watermark Banner */
  .watermark-strip {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.6rem;
    margin-bottom: 0.85rem;
  }
  .wm-box {
    background: #090f1d;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.55rem 0.75rem;
  }
  .wm-label { font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase; display: block; }
  .wm-val { font-size: 0.78rem; font-weight: 700; color: #e2e8f0; font-family: monospace; }
  .wm-fp { color: var(--accent-gold); cursor: pointer; text-decoration: underline dotted; }

  pre#out {
    background: #050811;
    border: 1px solid #1e293b;
    padding: 1rem;
    border-radius: 8px;
    color: #34d399;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
    min-height: 190px;
    max-height: 260px;
    overflow: auto;
    white-space: pre-wrap;
    line-height: 1.55;
    box-shadow: inset 0 2px 10px rgba(0,0,0,0.6);
  }
  pre#out.error-out {
    color: #fb7185;
    border-color: rgba(244, 63, 94, 0.5);
    background: rgba(244, 63, 94, 0.06);
  }

  /* Forensic Canary Inspector */
  .forensic-box {
    margin-top: 1rem;
    padding-top: 0.9rem;
    border-top: 1px solid rgba(51, 65, 85, 0.6);
  }
  .forensic-row { display: flex; gap: 0.6rem; margin-top: 0.5rem; }
  .forensic-input {
    flex: 1;
    background: #090f1d;
    border: 1px solid var(--border);
    color: #fff;
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.8rem;
  }
  .trace-btn {
    background: var(--accent-cyan);
    color: #041019;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-weight: 700;
    font-size: 0.78rem;
    cursor: pointer;
  }
  .trace-result {
    margin-top: 0.6rem;
    font-size: 0.76rem;
    padding: 0.6rem 0.8rem;
    border-radius: 6px;
    display: none;
  }

  /* Audit Trail Table */
  .audit-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.78rem;
    font-family: monospace;
  }
  .audit-table th {
    text-align: left;
    padding: 0.6rem 0.75rem;
    background: #090f1d;
    color: var(--text-muted);
    font-size: 0.7rem;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
  }
  .audit-table td {
    padding: 0.65rem 0.75rem;
    border-bottom: 1px solid rgba(51, 65, 85, 0.4);
  }
  .ev-badge {
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.68rem;
  }
  .ev-ok { background: rgba(16, 185, 129, 0.18); color: #34d399; }
  .ev-honey { background: rgba(244, 63, 94, 0.25); color: #fda4af; border: 1px solid #f43f5e; }
  .ev-deny { background: rgba(245, 158, 11, 0.2); color: #fcd34d; }

  .toast {
    position: fixed;
    bottom: 1.5rem;
    right: 1.5rem;
    padding: 0.85rem 1.2rem;
    border-radius: 10px;
    font-size: 0.82rem;
    font-weight: 700;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    display: none;
    z-index: 999;
  }
  @media (max-width: 900px) {
    .workspace, .telemetry-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="topbar">
    <div class="brand">
      <div class="brand-icon">CD</div>
      <div>
        <h1>CanaryDocs Gateway</h1>
        <p>Zero-Trust RBAC Enforcement, Dynamic Canary Fingerprinting & Honeytoken Tripwire</p>
      </div>
    </div>
    <div class="status-pill">
      <span class="dot"></span>
      <span>SOC ENGINE ONLINE &bull; SHA-256 WATERMARKING ACTIVE</span>
    </div>
  </div>

  <!-- Live Security Telemetry -->
  <div class="telemetry-grid">
    <div class="stat-card">
      <div>
        <div class="stat-label">Active Session Clearance</div>
        <div class="stat-value" id="stat-clearance" style="color:#38bdf8">L1</div>
      </div>
      <span class="stat-badge" id="stat-role-badge" style="background:rgba(56,189,248,0.15);color:#38bdf8">Employee</span>
    </div>
    <div class="stat-card">
      <div>
        <div class="stat-label">Watermarked Docs Issued</div>
        <div class="stat-value" id="stat-downloads" style="color:#34d399">0</div>
      </div>
      <span class="stat-badge" style="background:rgba(16,185,129,0.15);color:#34d399">SHA-256</span>
    </div>
    <div class="stat-card">
      <div>
        <div class="stat-label">Honeytoken Tripwires</div>
        <div class="stat-value" id="stat-honey" style="color:#fb7185">0</div>
      </div>
      <span class="stat-badge" style="background:rgba(244,63,94,0.15);color:#fb7185">L99 Bait</span>
    </div>
    <div class="stat-card">
      <div>
        <div class="stat-label">Total Security Events</div>
        <div class="stat-value" id="stat-events" style="color:#fbbf24">0</div>
      </div>
      <span class="stat-badge" style="background:rgba(245,158,11,0.15);color:#fbbf24">Audit Ledger</span>
    </div>
  </div>

  <!-- Persona Switcher -->
  <div class="persona-bar">
    <div>
      <div style="font-size:0.85rem;font-weight:700;">Identity & Clearance Simulation</div>
      <div style="font-size:0.74rem;color:var(--text-muted)">Switch active bearer token to test Role-Based Access Control (RBAC) and Audit privileges</div>
    </div>
    <div class="persona-cards">
      <button class="persona-btn active" id="btn-token_alice" onclick="selectPersona('token_alice')">
        <div class="avatar" style="background:rgba(6,182,212,0.2);color:#22d3ee">AL</div>
        <div>
          <span class="p-name">Alice (USR-101)</span>
          <span class="p-role">Employee &bull; Clearance L1</span>
        </div>
      </button>
      <button class="persona-btn" id="btn-token_bob" onclick="selectPersona('token_bob')">
        <div class="avatar" style="background:rgba(139,92,246,0.25);color:#c084fc">BM</div>
        <div>
          <span class="p-name">Bob (USR-102)</span>
          <span class="p-role">Manager &bull; Clearance L2</span>
        </div>
      </button>
      <button class="persona-btn" id="btn-token_eve" onclick="selectPersona('token_eve')">
        <div class="avatar" style="background:rgba(16,185,129,0.2);color:#34d399">EC</div>
        <div>
          <span class="p-name">Eve (USR-999)</span>
          <span class="p-role">Contractor &bull; Clearance L0</span>
        </div>
      </button>
    </div>
    <!-- Hidden select preserved for backward compatibility -->
    <select id="token" onchange="loadDocs()" style="display:none">
      <option value="token_alice">Alice (Employee - L1)</option>
      <option value="token_bob">Bob (Manager - L2)</option>
      <option value="token_eve">Eve (Contractor - L0)</option>
    </select>
  </div>

  <!-- Main Workspace -->
  <div class="workspace">
    <!-- Left: Vault Repository -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">Protected Document Vault</div>
          <div class="panel-sub">Assets filtered by clearance policy + active deception decoys</div>
        </div>
        <label style="font-size:0.74rem;color:var(--text-muted);display:flex;align-items:center;gap:0.35rem;cursor:pointer">
          <input type="checkbox" id="showAllToggle" onchange="loadDocs()" checked> Show all tiers
        </label>
      </div>
      <div id="docs" class="doc-list"></div>
    </div>

    <!-- Right: Watermark Terminal + Forensic Tracer -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">Cryptographic Canary Output</div>
          <div class="panel-sub">Real-time document payload with embedded attribution header</div>
        </div>
        <button onclick="copyOutput()" style="background:#1e293b;color:#cbd5e1;border:1px solid #334155;padding:0.35rem 0.7rem;border-radius:6px;font-size:0.72rem;cursor:pointer">Copy Payload</button>
      </div>

      <div class="watermark-strip">
        <div class="wm-box">
          <span class="wm-label">Issued Identity</span>
          <span class="wm-val" id="wm-user">—</span>
        </div>
        <div class="wm-box">
          <span class="wm-label">UTC Timestamp</span>
          <span class="wm-val" id="wm-time">—</span>
        </div>
        <div class="wm-box">
          <span class="wm-label">Canary Fingerprint (Click to Trace)</span>
          <span class="wm-val wm-fp" id="wm-fp" onclick="fillAndTrace()">—</span>
        </div>
      </div>

      <pre id="out">Select a document from the vault to generate a watermarked copy...</pre>

      <!-- Leak Attribution Tracer -->
      <div class="forensic-box">
        <div style="font-size:0.8rem;font-weight:700;color:#e2e8f0">Forensic Leak Investigator (Canary Attribution)</div>
        <div style="font-size:0.72rem;color:var(--text-muted)">Paste any 12-char Canary Fingerprint hash from a leaked document to identify the source user</div>
        <div class="forensic-row">
          <input type="text" id="fpInput" class="forensic-input" placeholder="e.g. e861f659b419">
          <button class="trace-btn" onclick="traceLeak()">Trace Fingerprint</button>
        </div>
        <div id="traceResult" class="trace-result"></div>
      </div>
    </div>
  </div>

  <!-- Audit Trail -->
  <div class="panel">
    <div class="panel-header">
      <div>
        <div class="panel-title">Immutable Security Audit Trail (Manager L2 Only)</div>
        <div class="panel-sub">Real-time telemetry of authorized downloads, RBAC blocks, and Honeytoken alerts</div>
      </div>
      <span id="audit-access-pill" class="tier-badge tier-2">L2 MANAGER REQUIRED</span>
    </div>
    <div id="logs" style="font-family:monospace;font-size:12px"></div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
function showToast(msg, isError) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  t.style.background = isError ? 'rgba(244, 63, 94, 0.95)' : 'rgba(16, 185, 129, 0.95)';
  t.style.color = '#fff';
  setTimeout(() => { t.style.display = 'none'; }, 3200);
}

function selectPersona(tokenVal) {
  document.getElementById('token').value = tokenVal;
  ['token_alice', 'token_bob', 'token_eve'].forEach(id => {
    document.getElementById('btn-' + id).classList.toggle('active', id === tokenVal);
  });
  loadDocs();
}

async function updateTelemetry() {
  const t = document.getElementById('token').value;
  try {
    const r = await fetch('/api/telemetry', { headers: { Authorization: t } });
    if (r.ok) {
      const d = await r.json();
      document.getElementById('stat-downloads').textContent = d.downloads_issued;
      document.getElementById('stat-honey').textContent = d.honeytoken_alerts;
      document.getElementById('stat-events').textContent = d.total_events;
    }
  } catch (e) {}
}

async function loadDocs() {
  const t = document.getElementById('token').value;
  const r = await fetch('/api/documents', { headers: { Authorization: t } });
  const d = await r.json();

  document.getElementById('stat-clearance').textContent = 'L' + d.clearance;
  document.getElementById('stat-role-badge').textContent = d.role;

  const showAll = document.getElementById('showAllToggle').checked;
  const list = showAll && d.all_docs ? d.all_docs : d.docs;

  document.getElementById('docs').innerHTML = list.map(x => {
    const tierClass = 'tier-' + x.clearance;
    const isTrap = x.is_trap || x.clearance === 99;
    const locked = !isTrap && x.clearance > d.clearance;
    const cardClass = isTrap ? 'doc-card trap-card' : 'doc-card';
    const btnClass = isTrap ? 'req-btn trap-btn' : (locked ? 'req-btn locked-btn' : 'req-btn');
    const btnLabel = isTrap ? 'Request (L99 Decoy)' : (locked ? 'Restricted (L' + x.clearance + ')' : 'Request Copy');
    const tierLabel = isTrap ? 'L99 HONEYTOKEN' : 'CLEARANCE L' + x.clearance;

    return `<div class="${cardClass}">
      <div class="doc-info">
        <div class="doc-title-row">
          <span class="doc-title">${x.title}</span>
          <span class="tier-badge ${tierClass}">${tierLabel}</span>
        </div>
        <div class="doc-meta">ID: ${x.id} &bull; Category: ${x.category || 'Standard'} &bull; Size: ${x.size || '12 KB'}</div>
      </div>
      <button class="${btnClass}" onclick="dl('${x.id}')">${btnLabel}</button>
    </div>`;
  }).join('');

  loadLogs();
  updateTelemetry();
}

async function dl(id) {
  const t = document.getElementById('token').value;
  const r = await fetch('/api/download/' + id, { headers: { Authorization: t } });
  const txt = await r.text();
  const outEl = document.getElementById('out');
  outEl.textContent = txt;

  if (!r.ok) {
    outEl.classList.add('error-out');
    document.getElementById('wm-user').textContent = 'ACCESS DENIED';
    document.getElementById('wm-time').textContent = new Date().toISOString().slice(11, 19) + ' UTC';
    document.getElementById('wm-fp').textContent = 'BLOCKED';
    showToast('Security Alert: Access Denied (' + r.status + ')', true);
  } else {
    outEl.classList.remove('error-out');
    const uMatch = txt.match(/ISSUED TO:\s*(.+)/);
    const tMatch = txt.match(/TIMESTAMP:\s*(.+)/);
    const fMatch = txt.match(/CANARY FINGERPRINT:\s*\[?([a-f0-9]+)\]?/i);
    document.getElementById('wm-user').textContent = uMatch ? uMatch[1] : 'Authorized';
    document.getElementById('wm-time').textContent = tMatch ? tMatch[1] : 'Now';
    document.getElementById('wm-fp').textContent = fMatch ? fMatch[1] : 'Generated';
    if (fMatch) document.getElementById('fpInput').value = fMatch[1];
    showToast('Watermarked document issued with Canary Fingerprint', false);
  }
  loadLogs();
  updateTelemetry();
}

function fillAndTrace() {
  const fp = document.getElementById('wm-fp').textContent;
  if (fp && fp !== '—' && fp !== 'BLOCKED') {
    document.getElementById('fpInput').value = fp;
    traceLeak();
  }
}

async function traceLeak() {
  const fp = document.getElementById('fpInput').value.trim();
  const box = document.getElementById('traceResult');
  if (!fp) return;
  const r = await fetch('/api/verify-canary?fp=' + encodeURIComponent(fp));
  box.style.display = 'block';
  if (!r.ok) {
    box.style.background = 'rgba(244, 63, 94, 0.15)';
    box.style.border = '1px solid rgba(244, 63, 94, 0.4)';
    box.style.color = '#fda4af';
    box.innerHTML = '<b>No Match Found:</b> Fingerprint hash does not match any issued document in the current session.';
    return;
  }
  const d = await r.json();
  const rec = d.record;
  box.style.background = 'rgba(6, 182, 212, 0.15)';
  box.style.border = '1px solid rgba(6, 182, 212, 0.45)';
  box.style.color = '#e2e8f0';
  box.innerHTML = `<b>LEAK SOURCE IDENTIFIED:</b> Fingerprint <code>[${rec.fingerprint}]</code> was issued to <b>${rec.user_name} (${rec.user_id})</b> [Role: ${rec.role}] for document <b>${rec.doc_title}</b> at <code>${rec.timestamp}</code>.`;
}

function copyOutput() {
  const txt = document.getElementById('out').textContent;
  navigator.clipboard.writeText(txt);
  showToast('Document payload copied to clipboard', false);
}

async function loadLogs() {
  const t = document.getElementById('token').value;
  const r = await fetch('/api/audit-logs', { headers: { Authorization: t } });
  const logsEl = document.getElementById('logs');
  if (!r.ok) {
    logsEl.innerHTML = '<div style="padding:1rem;background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.3);border-radius:8px;color:#fb7185">403 Forbidden: Persona lacks Manager clearance. Switch to <b>Bob (Manager - L2)</b> to inspect the full SOC Audit Trail.</div>';
    return;
  }
  const d = await r.json();
  if (!d.logs.length) {
    logsEl.innerHTML = '<div style="color:var(--text-muted);padding:0.75rem">No security events recorded yet.</div>';
    return;
  }
  logsEl.innerHTML = `<table class="audit-table">
    <thead><tr><th>Time (UTC)</th><th>Event Type</th><th>User ID</th><th>Target Asset</th><th>HTTP</th><th>Forensic Detail</th></tr></thead>
    <tbody>` + d.logs.map(l => {
      const evClass = l.event === 'DOWNLOAD_OK' ? 'ev-badge ev-ok' : (l.event === 'HONEYTOKEN_BREACH' ? 'ev-badge ev-honey' : 'ev-badge ev-deny');
      return `<tr>
        <td>${l.time}</td>
        <td><span class="${evClass}">${l.event}</span></td>
        <td><b>${l.user}</b></td>
        <td>${l.doc}</td>
        <td>${l.status}</td>
        <td>${l.detail}</td>
      </tr>`;
    }).join('') + `</tbody></table>`;
}

loadDocs();
</script>
</body>
</html>'''
