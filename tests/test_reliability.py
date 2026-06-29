import time
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def test_malformed_json_body_returns_envelope():
    client = TestClient(create_app())
    r = client.post("/api/v1/auth/handshake", json={"product": "x"})  # missing required fields
    assert r.status_code == 400
    assert r.json()["code"] == "invalid_request"


def test_oversized_field_does_not_crash():
    client = TestClient(create_app())
    huge = "A" * 2_000_000
    r = client.post("/api/v1/auth/handshake", json={
        "product": huge, "key": huge, "hwid": huge, "nonce": "n", "ts": int(time.time()), "sig": "x"})
    # Either rejected as bad product/sig or invalid — never a 500 crash.
    assert r.status_code in (400, 401, 429)
    assert r.json()["ok"] is False


def test_concurrent_handshakes_stay_consistent():
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        secret = p["app_secret"]
    client = TestClient(create_app())

    def one(i):
        ts = int(time.time()); nonce = f"n{i}"
        sig = security.sign(secret, "manager", raw, "HW1", nonce, ts)
        return client.post("/api/v1/auth/handshake", json={
            "product": "manager", "key": raw, "hwid": "HW1", "nonce": nonce, "ts": ts, "sig": sig}).status_code

    with ThreadPoolExecutor(max_workers=8) as ex:
        codes = list(ex.map(one, range(24)))
    # No 500s; each is either OK (200) or rate-limited (429) — never a crash.
    assert all(c in (200, 429) for c in codes)
