from . import license as lic


def check_clone(conn, key_id: int, now: int) -> bool:
    from .. import db
    ip_window = db.get_setting(conn, "clone_ip_window_seconds")
    max_ips = db.get_setting(conn, "clone_max_ips")
    concurrent_window = db.get_setting(conn, "clone_concurrent_window_seconds")
    cooldown = db.get_setting(conn, "clone_flag_cooldown_seconds")

    distinct_ips = conn.execute(
        "SELECT COUNT(DISTINCT ip) c FROM access_events WHERE key_id=? AND ts >= ?",
        (key_id, now - ip_window),
    ).fetchone()["c"]
    concurrent_ips = conn.execute(
        "SELECT COUNT(DISTINCT ip) c FROM access_events WHERE key_id=? AND ts >= ?",
        (key_id, now - concurrent_window),
    ).fetchone()["c"]

    suspicious = distinct_ips > max_ips or concurrent_ips >= 2
    if not suspicious:
        return False

    recent_flag = conn.execute(
        "SELECT 1 FROM audit_logs WHERE event_type='clone_suspected' AND key_id=? AND ts >= ?",
        (key_id, now - cooldown),
    ).fetchone()
    if recent_flag:
        return False

    lic.audit(conn, "clone_suspected", key_id=key_id, severity="high",
              detail={"distinct_ips_window": distinct_ips, "concurrent_ips": concurrent_ips})
    return True
