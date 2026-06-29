import time

from fastapi import APIRouter, Request

from .. import db, security
from ..envelope import ApiError, ok_env
from ..models import HandshakeReq
from ..ratelimit import limiter
from ..services import license as lic

router = APIRouter(prefix="/api/v1")


@router.get("/meta/health")
def health():
    return ok_env({"status": "alive"})


@router.get("/meta/time")
def server_time():
    return ok_env({"ts": int(time.time())})


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"


def _check_ts(conn, ts: int) -> None:
    now = int(time.time())
    window = db.get_setting(conn, "auth_ts_window_seconds")
    if abs(now - ts) > window:
        raise ApiError(400, "invalid_request", "stale timestamp")


def _consume_nonce(conn, nonce: str) -> None:
    now = int(time.time())
    prune = db.get_setting(conn, "nonce_prune_seconds")
    conn.execute("DELETE FROM used_nonces WHERE seen_at < ?", (now - prune,))
    exists = conn.execute("SELECT 1 FROM used_nonces WHERE nonce=?", (nonce,)).fetchone()
    if exists:
        raise ApiError(400, "invalid_request", "nonce reused")
    conn.execute("INSERT INTO used_nonces(nonce, seen_at) VALUES (?,?)", (nonce, now))


def _rate_limit(conn, bucket: str) -> None:
    now = int(time.time())
    limit = db.get_setting(conn, "rate_limit_auth_per_min")
    if not limiter.allow(bucket, limit=limit, window=60, now=now):
        raise ApiError(429, "rate_limited", "too many requests")


@router.post("/auth/handshake")
def handshake(req: HandshakeReq, request: Request):
    ip = _client_ip(request)
    with db.db() as conn:
        _rate_limit(conn, f"hs:{ip}")
        _check_ts(conn, req.ts)
        prod = lic.get_product(conn, req.product)
        if prod is None or not prod["active"]:
            raise ApiError(401, "auth_failed", "unknown product")
        if not security.verify_sig(prod["app_secret"], req.sig,
                                   req.product, req.key, req.hwid, req.nonce, req.ts):
            raise ApiError(401, "auth_failed", "bad signature")
        _consume_nonce(conn, req.nonce)
        key_row = lic.get_key_by_raw(conn, req.key)
        if key_row is None:
            raise ApiError(401, "auth_failed", "invalid key")

        challenge_id = security.new_token()
        server_nonce = security.new_nonce()
        ttl = db.get_setting(conn, "challenge_ttl_seconds")
        conn.execute(
            "INSERT INTO challenges(id, server_nonce, key_id, hwid, ip, expires_at, used) "
            "VALUES (?,?,?,?,?,?,0)",
            (challenge_id, server_nonce, key_row["id"], req.hwid, ip,
             int(time.time()) + ttl),
        )
    return ok_env({"challenge_id": challenge_id, "server_nonce": server_nonce, "ttl": ttl})
