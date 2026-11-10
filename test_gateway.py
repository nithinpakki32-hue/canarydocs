from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_unauthenticated_request_rejected():
    res = client.get("/api/documents/DOC-001/download")
    assert res.status_code == 401

def test_clearance_l0_blocked_from_l1_document():
    res = client.get("/api/documents/DOC-002/download", headers={"Authorization": "token_eve"})
    assert res.status_code == 403

def test_honeytoken_triggers_immediate_alarm():
    res = client.get("/api/documents/DOC-HONEY/download", headers={"Authorization": "token_alice"})
    assert res.status_code == 403

def test_authorized_download_contains_dynamic_watermark():
    res = client.get("/api/documents/DOC-003/download", headers={"Authorization": "token_bob"})
    assert res.status_code == 200
    assert "ISSUED TO: Bob (Manager)" in res.text
    assert "CANARY FINGERPRINT:" in res.text

def test_audit_log_access_restricted_to_managers():
    res_alice = client.get("/api/audit-logs", headers={"Authorization": "token_alice"})
    assert res_alice.status_code == 403
    res_bob = client.get("/api/audit-logs", headers={"Authorization": "token_bob"})
    assert res_bob.status_code == 200
