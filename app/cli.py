import argparse
import time

from . import db, security
from .config import settings
from .services import license as lic


def seed_admin() -> bool:
    db.init_db()
    with db.db() as conn:
        exists = conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone()
        if exists:
            return False
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?,?,?)",
            (settings.admin_username, security.hash_password(settings.admin_password), int(time.time())),
        )
    return True


def cmd_create_product(slug, name, prefix, cooldown_days=None) -> dict:
    db.init_db()
    with db.db() as conn:
        p = lic.create_product(conn, slug, name, prefix, cooldown_days)
        return dict(p)


def cmd_upload_payload(product, resource, path) -> int:
    db.init_db()
    from .services import payload as pl
    with open(path, "rb") as fh:
        data = fh.read()
    with db.db() as conn:
        prod = lic.get_product(conn, product)
        if prod is None:
            raise SystemExit(f"unknown product: {product}")
        pl.upsert_payload(conn, prod["id"], resource, data)
    return len(data)


def cmd_create_key(product, days, count=1, note="") -> list[str]:
    db.init_db()
    out = []
    with db.db() as conn:
        prod = lic.get_product(conn, product)
        if prod is None:
            raise SystemExit(f"unknown product: {product}")
        for _ in range(count):
            out.append(lic.create_key(conn, prod["id"], days * 86400, note))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("seed-admin")

    p = sub.add_parser("create-product")
    p.add_argument("--slug", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--prefix", required=True)
    p.add_argument("--cooldown-days", type=int, default=None)

    k = sub.add_parser("create-key")
    k.add_argument("--product", required=True)
    k.add_argument("--days", type=int, required=True)
    k.add_argument("--count", type=int, default=1)
    k.add_argument("--note", default="")

    up = sub.add_parser("upload-payload")
    up.add_argument("--product", required=True)
    up.add_argument("--resource", required=True)
    up.add_argument("--file", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "seed-admin":
        print("created" if seed_admin() else "admin already exists")
    elif args.cmd == "create-product":
        prod = cmd_create_product(args.slug, args.name, args.prefix, args.cooldown_days)
        print(f"product '{prod['slug']}' created. app_secret={prod['app_secret']}")
    elif args.cmd == "create-key":
        for raw in cmd_create_key(args.product, args.days, args.count, args.note):
            print(raw)
    elif args.cmd == "upload-payload":
        n = cmd_upload_payload(args.product, args.resource, args.file)
        print(f"uploaded {n} bytes to {args.product}/{args.resource}")


if __name__ == "__main__":
    main()
