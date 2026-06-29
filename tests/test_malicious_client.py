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


def _handshake(client, secret, raw, hwid="HW1", nonce=None, ts=None):
    ts = ts or int(time.time()); nonce = nonce or security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig})


def test_forged_signature_without_secret_is_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    ts = int(time.time())
    sig = security.sign("attacker-guessed-secret", "manager", raw, "HW1", "n", ts)
    r = client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": "HW1", "nonce": "n", "ts": ts, "sig": sig})
    assert r.status_code == 401 and r.json()["code"] == "auth_failed"


def test_replayed_handshake_is_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    ts = int(time.time()); nonce = "fixed-nonce"
    sig = security.sign(secret, "manager", raw, "HW1", nonce, ts)
    body = {"product": "manager", "key": raw, "hwid": "HW1", "nonce": nonce, "ts": ts, "sig": sig}
    assert client.post("/api/v1/auth/handshake", json=body).json()["ok"] is True
    assert client.post("/api/v1/auth/handshake", json=body).json()["code"] == "invalid_request"


def test_replayed_challenge_answer_is_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    hs = _handshake(client, secret, raw).json()["data"]
    ts2 = int(time.time())
    answer = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, "HW1", ts2)
    body = {"challenge_id": hs["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts2, "answer_sig": answer}
    assert client.post("/api/v1/auth/verify", json=body).json()["ok"] is True
    # reusing the same challenge again must fail (single-use)
    assert client.post("/api/v1/auth/verify", json=body).status_code == 401


def test_cloned_hwid_cannot_run_in_parallel():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    # legit machine HW1 authenticates
    hs = _handshake(client, secret, raw, hwid="HW1").json()["data"]
    ts = int(time.time())
    ans = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, "HW1", ts)
    tok1 = client.post("/api/v1/auth/verify", json={
        "challenge_id": hs["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts, "answer_sig": ans}
    ).json()["data"]["token"]
    # attacker spoofs the SAME hwid (HW1) and authenticates -> supersedes session
    hs2 = _handshake(client, secret, raw, hwid="HW1").json()["data"]
    ts2 = int(time.time())
    ans2 = security.sign(secret, hs2["challenge_id"], hs2["server_nonce"], raw, "HW1", ts2)
    client.post("/api/v1/auth/verify", json={
        "challenge_id": hs2["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts2, "answer_sig": ans2})
    # original token is now revoked -> parallel use impossible
    r = client.get("/api/v1/license", headers={"Authorization": f"Bearer {tok1}"})
    assert r.status_code == 401


def test_different_hwid_is_rejected_and_logged():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    # activate on HW1
    hs = _handshake(client, secret, raw, hwid="HW1").json()["data"]
    ts = int(time.time())
    ans = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, "HW1", ts)
    client.post("/api/v1/auth/verify", json={
        "challenge_id": hs["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts, "answer_sig": ans})
    # HW2 tries
    hs2 = _handshake(client, secret, raw, hwid="HW2").json()["data"]
    ts2 = int(time.time())
    ans2 = security.sign(secret, hs2["challenge_id"], hs2["server_nonce"], raw, "HW2", ts2)
    r = client.post("/api/v1/auth/verify", json={
        "challenge_id": hs2["challenge_id"], "key": raw, "hwid": "HW2", "ts": ts2, "answer_sig": ans2})
    assert r.status_code == 403 and r.json()["code"] == "hwid_mismatch"
