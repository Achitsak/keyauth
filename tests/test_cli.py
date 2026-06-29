from app import db, cli, security


def test_seed_admin_idempotent():
    assert cli.seed_admin() is True
    assert cli.seed_admin() is False  # already exists
    with db.db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"]
    assert n == 1


def test_create_product_and_keys():
    prod = cli.cmd_create_product(slug="manager", name="Manager", prefix="MASTERP")
    assert prod["app_secret"]
    keys = cli.cmd_create_key(product="manager", days=30, count=3)
    assert len(keys) == 3
    with db.db() as conn:
        row = conn.execute("SELECT duration_seconds FROM license_keys LIMIT 1").fetchone()
    assert row["duration_seconds"] == 30 * 86400
