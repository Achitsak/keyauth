from app import db


def test_tables_created():
    with db.db() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    names = {r["name"] for r in rows}
    for t in ["products", "license_keys", "admins", "sessions",
              "challenges", "used_nonces", "audit_logs", "settings", "payloads"]:
        assert t in names


def test_settings_default_then_override():
    with db.db() as conn:
        assert db.get_setting(conn, "session_ttl_seconds") == 3600
        db.set_setting(conn, "session_ttl_seconds", 1800)
        assert db.get_setting(conn, "session_ttl_seconds") == 1800
