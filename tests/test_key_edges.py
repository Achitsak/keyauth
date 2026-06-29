import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap(duration=3600):
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], duration)
        secret = p["app_secret"]
    return secret, raw


def _handshake(client, secret, raw, hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig})


def test_banned_key_rejected_at_handshake():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    with db.db() as conn:
        conn.execute("UPDATE license_keys SET status='banned'")
    r = _handshake(client, secret, raw)
    assert r.status_code == 403 and r.json()["code"] == "banned"


def test_expiry_exact_boundary_is_expired():
    # is_expired uses now >= expires_at, so exactly-at-expiry counts as expired
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 100)
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HW1", 1000)  # expires_at = 1100
        row = lic.get_key_by_raw(conn, raw)
    assert lic.is_expired(row, 1100) is True
    assert lic.is_expired(row, 1099) is False


def test_reset_then_rebind_new_hwid_succeeds():
    secret, raw = _bootstrap()
    client = TestClient(create_app())

    def full_auth(hwid):
        hs = _handshake(client, secret, raw, hwid=hwid).json()["data"]
        ts = int(time.time()); ans = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, hwid, ts)
        return client.post("/api/v1/auth/verify", json={
            "challenge_id": hs["challenge_id"], "key": raw, "hwid": hwid, "ts": ts, "answer_sig": ans})

    assert full_auth("HW1").json()["ok"] is True
    # reset hwid directly (cooldown bypass via DB for this unit test)
    with db.db() as conn:
        conn.execute("UPDATE license_keys SET hwid=NULL")
    assert full_auth("HW2").json()["ok"] is True  # re-binds to new machine
    with db.db() as conn:
        assert lic.get_key_by_raw(conn, raw)["hwid"] == "HW2"
