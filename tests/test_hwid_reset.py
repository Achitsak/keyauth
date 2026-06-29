import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap(cooldown_days=None):
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP", cooldown_days=cooldown_days)
        raw = lic.create_key(conn, p["id"], 3600)
        secret = p["app_secret"]
        # pre-activate + bind HW1
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HW1", int(time.time()))
    return secret, raw


def _reset_body(secret, raw, hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return {"product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}


def test_reset_success_then_cooldown():
    secret, raw = _bootstrap(cooldown_days=7)
    client = TestClient(create_app())
    r = client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw))
    assert r.json()["data"]["reset"] is True
    with db.db() as conn:
        k = lic.get_key_by_raw(conn, raw)
        assert k["hwid"] is None and k["hwid_reset_count"] == 1
    r2 = client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw))
    assert r2.status_code == 429
    assert r2.json()["code"] == "cooldown"


def test_reset_allowed_when_cooldown_zero():
    secret, raw = _bootstrap(cooldown_days=0)
    client = TestClient(create_app())
    assert client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw)).json()["data"]["reset"]
    assert client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw)).json()["data"]["reset"]
