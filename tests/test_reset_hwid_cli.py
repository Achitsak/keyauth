import time
from app import db, cli
from app.services import license as lic


def test_cmd_reset_hwid_clears_and_revokes():
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HW1", int(time.time()))
        conn.execute("INSERT INTO sessions(token_hash, key_id, hwid, ip, issued_at, expires_at, revoked) "
                     "VALUES ('th', ?, 'HW1', '1.1.1.1', ?, ?, 0)",
                     (lic.get_key_by_raw(conn, raw)["id"], int(time.time()), int(time.time()) + 3600))
    assert cli.cmd_reset_hwid(key=raw) is True
    with db.db() as conn:
        k = lic.get_key_by_raw(conn, raw)
        assert k["hwid"] is None and k["hwid_reset_count"] == 1
        live = conn.execute("SELECT COUNT(*) c FROM sessions WHERE revoked=0").fetchone()["c"]
    assert live == 0


def test_cmd_reset_hwid_unknown_key():
    assert cli.cmd_reset_hwid(key="MASTERP-AAAAA-BBBBB-CCCCC-DDDDD") is False
