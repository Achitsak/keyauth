import time
from app import db
from app.services import license as lic
from app.services import detection as det


def _key(conn):
    p = lic.create_product(conn, "manager", "M", "MASTERP")
    raw = lic.create_key(conn, p["id"], 3600)
    return lic.get_key_by_raw(conn, raw)["id"]


def _ev(conn, kid, ip, ts):
    conn.execute("INSERT INTO access_events(key_id, ip, hwid, ts, kind) VALUES (?,?,?,?,'auth')",
                 (kid, ip, "HW1", ts))


def test_flags_ip_velocity():
    now = 10_000
    with db.db() as conn:
        kid = _key(conn)
        for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]):
            _ev(conn, kid, ip, now - i)  # 4 distinct IPs > clone_max_ips(3)
        flagged = det.check_clone(conn, kid, now)
        assert flagged is True
        n = conn.execute("SELECT COUNT(*) n FROM audit_logs WHERE event_type='clone_suspected'").fetchone()["n"]
    assert n == 1


def test_no_flag_single_ip():
    now = 10_000
    with db.db() as conn:
        kid = _key(conn)
        for i in range(5):
            _ev(conn, kid, "1.1.1.1", now - i)
        assert det.check_clone(conn, kid, now) is False


def test_flag_cooldown_prevents_duplicates():
    now = 10_000
    with db.db() as conn:
        kid = _key(conn)
        for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]):
            _ev(conn, kid, ip, now - i)
        assert det.check_clone(conn, kid, now) is True
        assert det.check_clone(conn, kid, now) is False  # within cooldown
        n = conn.execute("SELECT COUNT(*) n FROM audit_logs WHERE event_type='clone_suspected'").fetchone()["n"]
    assert n == 1
