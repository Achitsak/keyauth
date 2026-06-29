import json
import time

from .. import security


def create_product(conn, slug, name, key_prefix, cooldown_days=None):
    now = int(time.time())
    app_secret = security.new_token()
    conn.execute(
        "INSERT INTO products(slug, name, key_prefix, app_secret, "
        "hwid_reset_cooldown_days, active, created_at) VALUES (?,?,?,?,?,1,?)",
        (slug, name, key_prefix, app_secret, cooldown_days, now),
    )
    row = get_product(conn, slug)
    return dict(row) if row is not None else None


def get_product(conn, slug):
    return conn.execute("SELECT * FROM products WHERE slug=?", (slug,)).fetchone()


def create_key(conn, product_id, duration_seconds, note=""):
    prod = conn.execute("SELECT key_prefix FROM products WHERE id=?", (product_id,)).fetchone()
    raw = security.generate_key(prod["key_prefix"])
    now = int(time.time())
    conn.execute(
        "INSERT INTO license_keys(key_hash, key_prefix, product_id, duration_seconds, "
        "status, note, created_at) VALUES (?,?,?,?, 'unused', ?, ?)",
        (security.hash_key(raw), security.key_prefix_display(raw), product_id,
         duration_seconds, note, now),
    )
    return raw


def get_key_by_raw(conn, raw_key):
    return conn.execute(
        "SELECT * FROM license_keys WHERE key_hash=?", (security.hash_key(raw_key),)
    ).fetchone()


def is_expired(key_row, now: int) -> bool:
    exp = key_row["expires_at"]
    return exp is not None and now >= exp


def activate_if_new(conn, key_row, hwid, now) -> None:
    if key_row["status"] == "unused":
        conn.execute(
            "UPDATE license_keys SET status='active', hwid=?, hwid_set_at=?, "
            "activated_at=?, expires_at=? WHERE id=? AND status='unused'",
            (hwid, now, now, now + key_row["duration_seconds"], key_row["id"]),
        )


def audit(conn, event_type, key_id=None, hwid=None, ip=None, severity="info", detail=None):
    conn.execute(
        "INSERT INTO audit_logs(ts, event_type, key_id, hwid, ip, severity, detail_json) "
        "VALUES (?,?,?,?,?,?,?)",
        (int(time.time()), event_type, key_id, hwid, ip, severity,
         json.dumps(detail) if detail is not None else None),
    )
