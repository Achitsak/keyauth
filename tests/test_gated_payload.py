import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.services import payload as pl
from app.ratelimit import limiter


def _setup_key_and_payload(product="manager", resource="main.lua", body=b"SECRET-SCRIPT"):
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, product, "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        pl.upsert_payload(conn, p["id"], resource, body)
        secret = p["app_secret"]
    return secret, raw


def _token(client, secret, raw, product="manager", hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, product, raw, hwid, nonce, ts)
    hs = client.post("/api/v1/auth/handshake", json={
        "product": product, "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}).json()
    cid, sn = hs["data"]["challenge_id"], hs["data"]["server_nonce"]
    ts2 = int(time.time()); ans = security.sign(secret, cid, sn, raw, hwid, ts2)
    return client.post("/api/v1/auth/verify", json={
        "challenge_id": cid, "key": raw, "hwid": hwid, "ts": ts2, "answer_sig": ans}).json()["data"]["token"]


def test_payload_requires_session():
    _setup_key_and_payload()
    client = TestClient(create_app())
    assert client.get("/api/v1/files/manager/main.lua").status_code == 401


def test_payload_delivered_to_valid_session():
    secret, raw = _setup_key_and_payload()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    r = client.get("/api/v1/files/manager/main.lua", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.content == b"SECRET-SCRIPT"


def test_wrong_product_rejected():
    secret, raw = _setup_key_and_payload()
    client = TestClient(create_app())
    with db.db() as conn:
        p2 = lic.create_product(conn, "other", "Other", "OTHER")
        pl.upsert_payload(conn, p2["id"], "main.lua", b"OTHER-SECRET")
    tok = _token(client, secret, raw)  # key is for 'manager'
    r = client.get("/api/v1/files/other/main.lua", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_missing_resource_404():
    secret, raw = _setup_key_and_payload()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    r = client.get("/api/v1/files/manager/nope.lua", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 404 and r.json()["code"] == "not_found"
