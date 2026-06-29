import time

from fastapi import APIRouter, Request

from .. import db, security
from ..envelope import ApiError, ok_env
from ..models import HandshakeReq, VerifyReq
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


def _authed_session(conn, request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ApiError(401, "auth_failed", "missing token")
    token = auth[7:]
    sess = conn.execute(
        "SELECT * FROM sessions WHERE token_hash=?", (security.hash_token(token),)
    ).fetchone()
    now = int(time.time())
    if sess is None or sess["revoked"] or now >= sess["expires_at"]:
        raise ApiError(401, "auth_failed", "invalid session")
    return sess


@router.get("/license")
def license_status(request: Request):
    with db.db() as conn:
        sess = _authed_session(conn, request)
        k = conn.execute("SELECT * FROM license_keys WHERE id=?", (sess["key_id"],)).fetchone()
        prod = conn.execute("SELECT slug FROM products WHERE id=?", (k["product_id"],)).fetchone()
        data = {"product": prod["slug"], "status": k["status"], "expires_at": k["expires_at"],
                "hwid": k["hwid"], "hwid_reset_count": k["hwid_reset_count"]}
    return ok_env(data)


@router.post("/auth/heartbeat")
def heartbeat(request: Request):
    with db.db() as conn:
        sess = _authed_session(conn, request)
        k = conn.execute("SELECT * FROM license_keys WHERE id=?", (sess["key_id"],)).fetchone()
        if k["status"] == "banned":
            raise ApiError(403, "banned", "key banned")
        if lic.is_expired(k, int(time.time())):
            conn.execute("UPDATE license_keys SET status='expired' WHERE id=?", (k["id"],))
            raise ApiError(403, "expired", "license expired")
        exp = k["expires_at"]
    return ok_env({"valid": True, "key_expires_at": exp})


@router.delete("/auth/session")
def logout(request: Request):
    with db.db() as conn:
        sess = _authed_session(conn, request)
        conn.execute("UPDATE sessions SET revoked=1 WHERE id=?", (sess["id"],))
    return ok_env({"revoked": True})


@router.post("/auth/verify")
def verify(req: VerifyReq, request: Request):
    ip = _client_ip(request)
    with db.db() as conn:
        _rate_limit(conn, f"vf:{ip}")
        _check_ts(conn, req.ts)
        now = int(time.time())

        ch = conn.execute("SELECT * FROM challenges WHERE id=?", (req.challenge_id,)).fetchone()
        if ch is None or ch["used"] or now >= ch["expires_at"]:
            raise ApiError(401, "auth_failed", "invalid challenge")
        conn.execute("UPDATE challenges SET used=1 WHERE id=?", (req.challenge_id,))

        key_row = lic.get_key_by_raw(conn, req.key)
        if key_row is None or key_row["id"] != ch["key_id"]:
            raise ApiError(401, "auth_failed", "invalid key")
        prod = conn.execute("SELECT * FROM products WHERE id=?", (key_row["product_id"],)).fetchone()

        if not security.verify_sig(prod["app_secret"], req.answer_sig,
                                   req.challenge_id, ch["server_nonce"], req.key, req.hwid, req.ts):
            raise ApiError(401, "auth_failed", "bad challenge answer")

        if key_row["status"] == "banned":
            raise ApiError(403, "banned", "key banned")

        if key_row["status"] == "unused":
            lic.activate_if_new(conn, key_row, req.hwid, now)
            key_row = lic.get_key_by_raw(conn, req.key)
        elif key_row["hwid"] != req.hwid:
            lic.audit(conn, "clone_attempt", key_id=key_row["id"], hwid=req.hwid, ip=ip, severity="high",
                      detail={"bound": key_row["hwid"], "attempted": req.hwid})
            raise ApiError(403, "hwid_mismatch", "key bound to another machine")

        if lic.is_expired(key_row, now):
            conn.execute("UPDATE license_keys SET status='expired' WHERE id=?", (key_row["id"],))
            raise ApiError(403, "expired", "license expired")

        # single active session: revoke any prior live sessions for this key
        conn.execute("UPDATE sessions SET revoked=1 WHERE key_id=? AND revoked=0", (key_row["id"],))

        token = security.new_token()
        ttl = db.get_setting(conn, "session_ttl_seconds")
        sess_exp = now + ttl
        conn.execute(
            "INSERT INTO sessions(token_hash, key_id, hwid, ip, issued_at, expires_at, revoked) "
            "VALUES (?,?,?,?,?,?,0)",
            (security.hash_token(token), key_row["id"], req.hwid, ip, now, sess_exp),
        )
        lic.audit(conn, "login", key_id=key_row["id"], hwid=req.hwid, ip=ip)
        key_exp = key_row["expires_at"]
    return ok_env({"token": token, "expires_at": sess_exp,
                   "product": req.key.split("-")[0], "key_expires_at": key_exp})
