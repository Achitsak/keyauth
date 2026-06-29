import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap(duration=3600):
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], duration)
        secret = p["app_secret"]
    return secret, raw


def _full_auth(client, secret, raw, hwid="HW1"):
    ts = int(time.time())
    nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    hs = client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid,
        "nonce": nonce, "ts": ts, "sig": sig}).json()
    cid = hs["data"]["challenge_id"]
    snonce = hs["data"]["server_nonce"]
    ts2 = int(time.time())
    answer = security.sign(secret, cid, snonce, raw, hwid, ts2)
    return client.post("/api/v1/auth/verify", json={
        "challenge_id": cid, "key": raw, "hwid": hwid,
        "ts": ts2, "answer_sig": answer})


def test_verify_success_issues_token():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    r = _full_auth(client, secret, raw)
    body = r.json()
    assert body["ok"] is True
    assert body["data"]["token"]


def test_verify_hwid_mismatch_after_activation():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    assert _full_auth(client, secret, raw, hwid="HW1").json()["ok"] is True
    r = _full_auth(client, secret, raw, hwid="HW2")
    assert r.status_code == 403
    assert r.json()["code"] == "hwid_mismatch"
    with db.db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM audit_logs WHERE event_type='clone_attempt'").fetchone()["c"]
    assert n == 1


def test_verify_expired_key():
    secret, raw = _bootstrap(duration=1)
    client = TestClient(create_app())
    assert _full_auth(client, secret, raw).json()["ok"] is True
    time.sleep(2)
    r = _full_auth(client, secret, raw)
    assert r.json()["code"] == "expired"


def test_single_active_session():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    t1 = _full_auth(client, secret, raw).json()["data"]["token"]
    t2 = _full_auth(client, secret, raw).json()["data"]["token"]
    assert t1 != t2
    with db.db() as conn:
        active = conn.execute("SELECT COUNT(*) c FROM sessions WHERE revoked=0").fetchone()["c"]
    assert active == 1
