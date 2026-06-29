from app import db, cli
from app.services import license as lic
from app.services import payload as pl
from app import payload_crypto as pc


def test_upsert_and_get_roundtrip():
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        pl.upsert_payload(conn, p["id"], "main.lua", b"print('hi')")
        row = pl.get_payload(conn, p["id"], "main.lua")
        assert pc.decrypt_payload(row["ciphertext"], row["nonce"]) == b"print('hi')"


def test_upsert_overwrites(tmp_path):
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        pl.upsert_payload(conn, p["id"], "main.lua", b"v1")
        pl.upsert_payload(conn, p["id"], "main.lua", b"v2")
        row = pl.get_payload(conn, p["id"], "main.lua")
        assert pc.decrypt_payload(row["ciphertext"], row["nonce"]) == b"v2"


def test_cli_upload(tmp_path):
    f = tmp_path / "script.lua"
    f.write_bytes(b"local x = 1")
    cli.cmd_create_product(slug="manager", name="Manager", prefix="MASTERP")
    n = cli.cmd_upload_payload(product="manager", resource="script.lua", path=str(f))
    assert n == 11
