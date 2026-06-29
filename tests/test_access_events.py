import time
from types import SimpleNamespace
from app import db
from app.routers import client as c
from app.config import settings
from app.services import license as lic


def _req(ip, xff=None):
    headers = {}
    if xff:
        headers["X-Forwarded-For"] = xff
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers=headers)


def test_client_ip_direct_vs_proxy():
    settings.trust_proxy = False
    assert c._client_ip(_req("1.2.3.4", xff="9.9.9.9, 8.8.8.8")) == "1.2.3.4"
    settings.trust_proxy = True
    try:
        assert c._client_ip(_req("1.2.3.4", xff="9.9.9.9, 8.8.8.8")) == "8.8.8.8"
    finally:
        settings.trust_proxy = False


def test_record_access_inserts():
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        k = lic.get_key_by_raw(conn, raw)
        c.record_access(conn, k["id"], "1.2.3.4", "HW1", "auth")
        n = conn.execute("SELECT COUNT(*) n FROM access_events WHERE key_id=?", (k["id"],)).fetchone()["n"]
    assert n == 1
