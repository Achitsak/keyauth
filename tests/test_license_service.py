import time
from app import db
from app.services import license as lic


def _setup():
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Masterp Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], duration_seconds=3600)
    return p, raw


def test_create_and_lookup_key():
    p, raw = _setup()
    with db.db() as conn:
        row = lic.get_key_by_raw(conn, raw)
        assert row["product_id"] == p["id"]
        assert row["status"] == "unused"


def test_activation_sets_expiry_and_hwid():
    p, raw = _setup()
    now = int(time.time())
    with db.db() as conn:
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HWID-1", now)
        row2 = lic.get_key_by_raw(conn, raw)
        assert row2["status"] == "active"
        assert row2["hwid"] == "HWID-1"
        assert row2["expires_at"] == now + 3600


def test_is_expired():
    p, raw = _setup()
    with db.db() as conn:
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HWID-1", 1000)
        row2 = lic.get_key_by_raw(conn, raw)
    assert lic.is_expired(row2, now=1000 + 3601)
    assert not lic.is_expired(row2, now=1000 + 10)
