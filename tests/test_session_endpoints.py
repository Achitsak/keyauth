import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap():
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        secret = p["app_secret"]
    return secret, raw


def _token(client, secret, raw, hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    hs = client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}).json()
    cid, snonce = hs["data"]["challenge_id"], hs["data"]["server_nonce"]
    ts2 = int(time.time()); answer = security.sign(secret, cid, snonce, raw, hwid, ts2)
    return client.post("/api/v1/auth/verify", json={
        "challenge_id": cid, "key": raw, "hwid": hwid, "ts": ts2, "answer_sig": answer}).json()["data"]["token"]


def test_license_status_requires_token():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    assert client.get("/api/v1/license").status_code == 401
    tok = _token(client, secret, raw)
    r = client.get("/api/v1/license", headers={"Authorization": f"Bearer {tok}"})
    assert r.json()["data"]["status"] == "active"


def test_heartbeat_ok():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    r = client.post("/api/v1/auth/heartbeat", headers={"Authorization": f"Bearer {tok}"})
    assert r.json()["data"]["valid"] is True


def test_revoked_session_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    with db.db() as conn:
        conn.execute("UPDATE sessions SET revoked=1")
    r = client.get("/api/v1/license", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401
