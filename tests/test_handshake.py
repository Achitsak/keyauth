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


def _handshake_body(secret, raw, hwid="HW1", ts=None, nonce="n1"):
    ts = ts or int(time.time())
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return {"product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}


def test_handshake_success():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    r = client.post("/api/v1/auth/handshake", json=_handshake_body(secret, raw))
    body = r.json()
    assert body["ok"] is True
    assert body["data"]["challenge_id"]
    assert body["data"]["server_nonce"]


def test_handshake_bad_signature():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    bad = _handshake_body(secret, raw)
    bad["sig"] = "deadbeef"
    r = client.post("/api/v1/auth/handshake", json=bad)
    assert r.status_code == 401
    assert r.json()["code"] == "auth_failed"


def test_handshake_stale_timestamp():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    old = int(time.time()) - 9999
    r = client.post("/api/v1/auth/handshake", json=_handshake_body(secret, raw, ts=old))
    assert r.json()["code"] == "invalid_request"


def test_handshake_replayed_nonce():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    body = _handshake_body(secret, raw)
    assert client.post("/api/v1/auth/handshake", json=body).json()["ok"] is True
    r2 = client.post("/api/v1/auth/handshake", json=body)
    assert r2.json()["code"] == "invalid_request"
