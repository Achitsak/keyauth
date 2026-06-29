import time

from .. import payload_crypto


def upsert_payload(conn, product_id: int, resource_slug: str, plaintext: bytes) -> None:
    ciphertext, nonce = payload_crypto.encrypt_payload(plaintext)
    conn.execute(
        "INSERT INTO payloads(product_id, resource_slug, ciphertext, nonce, created_at) "
        "VALUES (?,?,?,?,?) "
        "ON CONFLICT(product_id, resource_slug) DO UPDATE SET "
        "ciphertext=excluded.ciphertext, nonce=excluded.nonce, created_at=excluded.created_at",
        (product_id, resource_slug, ciphertext, nonce, int(time.time())),
    )


def get_payload(conn, product_id: int, resource_slug: str):
    return conn.execute(
        "SELECT * FROM payloads WHERE product_id=? AND resource_slug=?",
        (product_id, resource_slug),
    ).fetchone()
