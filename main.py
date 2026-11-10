import hashlib
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(title="CanaryDocs Gateway")

USERS = {
    "token_alice": {"id": "USR-101", "name": "Alice", "role": "Employee", "clearance": 1},
    "token_bob": {"id": "USR-102", "name": "Bob (Manager)", "role": "Manager", "clearance": 2},
    "token_eve": {"id": "USR-999", "name": "Eve (Contractor)", "role": "Contractor", "clearance": 0},
}

DOCS = {
    "DOC-001": {"id": "DOC-001", "title": "Public Policy Guidelines.txt", "clearance": 0, "is_trap": False, "body": "Zero-trust access policy guidelines."},
    "DOC-002": {"id": "DOC-002", "title": "Internal Engineering Roadmap.txt", "clearance": 1, "is_trap": False, "body": "Q4 Gateway migration targets."},
    "DOC-003": {"id": "DOC-003", "title": "Executive Financial Audit.txt", "clearance": 2, "is_trap": False, "body": "Restricted executive financial ledger."},
    "DOC-HONEY": {"id": "DOC-HONEY", "title": "Q3_Salaries_Unencrypted.xlsx", "clearance": 99, "is_trap": True, "body": "HONEYTOKEN_TRIPWIRE"},
}

LOGS = []

def log_event(event, uid, did, status, detail):
    LOGS.insert(0, {
        "time": datetime.utcnow().strftime("%H:%M:%S UTC"),
        "event": event, "user": uid, "doc": did, "status": status, "detail": detail
    })

def auth_user(authorization: Optional[str] = Header(None)):
    if not authorization or authorization not in USERS:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    return USERS[authorization]

@app.get("/api/documents")
def get_documents(authorization: Optional[str] = Header(None)):
    u = auth_user(authorization)
    return {"user": u["name"], "role": u["role"], "docs": [
        {"id": d["id"], "title": d["title"], "clearance": d["clearance"]}
        for d in DOCS.values() if d["clearance"] <= u["clearance"] or d["is_trap"]
    ]}

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
    log_event("DOWNLOAD_OK", u["id"], doc_id, 200, f"Watermark fingerprint: {fp}")
    return PlainTextResponse(f"=== {doc['title']} ===\nISSUED TO: {u['name']} ({u['id']})\nTIMESTAMP: {ts}\nCANARY FINGERPRINT: [{fp}]\n\n{doc['body']}")

@app.get("/api/audit-logs")
def get_logs(authorization: Optional[str] = Header(None)):
    u = auth_user(authorization)
    if u["role"] != "Manager":
        log_event("FORBIDDEN_AUDIT_VIEW", u["id"], "LOGS", 403, "Non-manager attempted to view audit ledger.")
        raise HTTPException(status_code=403, detail="Forbidden: Audit logs are restricted to Managers.")
    return {"logs": LOGS}

@app.get("/", response_class=HTMLResponse)
def index():
    return '''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CanaryDocs Gateway</title><style>body{background:#0f172a;color:#f1f5f9;font-family:sans-serif;padding:2rem}.wrap{max-width:900px;margin:0 auto}.card{background:#1e293b;padding:1rem;border-radius:8px;margin-bottom:1rem}.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}.row{display:flex;justify-content:space-between;align-items:center;background:#334155;padding:0.5rem;border-radius:6px;margin-bottom:0.5rem}button{background:#f59e0b;color:#0f172a;border:none;padding:0.4rem 0.8rem;border-radius:4px;font-weight:bold;cursor:pointer}pre{background:#020617;padding:1rem;border-radius:6px;color:#34d399;min-height:160px;overflow:auto;font-size:12px}select{background:#334155;color:#fff;padding:0.4rem;border-radius:4px;border:1px solid #475569}</style></head><body><div class="wrap"><h1 style="color:#fbbf24">CanaryDocs Gateway</h1><div class="card"><label><b>Active Persona:</b> </label><select id="token" onchange="loadDocs()"><option value="token_alice">Alice (Employee - L1)</option><option value="token_bob">Bob (Manager - L2)</option><option value="token_eve">Eve (Contractor - L0)</option></select></div><div class="grid"><div id="docs" class="card"></div><pre id="out">Select a document to request access...</pre></div><div class="card"><h3>Audit Trail (Manager Only)</h3><div id="logs" style="font-family:monospace;font-size:12px"></div></div></div><script>async function loadDocs(){const t=document.getElementById('token').value;const r=await fetch('/api/documents',{headers:{Authorization:t}});const d=await r.json();document.getElementById('docs').innerHTML=d.docs.map(x=>`<div class="row"><span>${x.title} (L${x.clearance})</span><button onclick="dl('${x.id}')">Request</button></div>`).join('');loadLogs();}async function dl(id){const t=document.getElementById('token').value;const r=await fetch('/api/download/'+id,{headers:{Authorization:t}});document.getElementById('out').textContent=await r.text();loadLogs();}async function loadLogs(){const t=document.getElementById('token').value;const r=await fetch('/api/audit-logs',{headers:{Authorization:t}});if(!r.ok){document.getElementById('logs').innerHTML='<span style="color:#fb7185">403 Forbidden: Persona lacks Manager clearance.</span>';return;}const d=await r.json();document.getElementById('logs').innerHTML=d.logs.map(l=>`<div>[${l.time}] [${l.event}] User:${l.user} - ${l.detail}</div>`).join('');}loadDocs();</script></body></html>'''
