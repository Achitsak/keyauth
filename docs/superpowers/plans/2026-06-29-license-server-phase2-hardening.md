# License Server — Phase 2: Gated Payload + Detection + Reliability (24/7) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the gated encrypted-payload endpoint (the core anti-crack), server-side clone detection, an operator HWID-reset path, DB performance optimization, and the reliability hardening needed to run 24/7 without crashing.

**Architecture:** Builds on the Phase 1 FastAPI/SQLite server (on `main`). Payloads are AES-256-GCM encrypted at rest (key derived from `SERVER_SECRET`) and served only through an authenticated session. Detection runs server-side from an `access_events` log. Reliability comes from: a catch-all exception handler (no request can crash the process), SQLite WAL + busy_timeout + tuned pragmas, bounded in-memory state with opportunistic pruning, graceful degradation of non-critical subsystems, and a Docker deployment with `restart: always`.

**Tech Stack:** Python 3.11+, FastAPI, SQLite (WAL), `cryptography` (AES-GCM), pytest. Single robust instance + auto-restart (no multi-instance HA in this phase).

## Global Constraints

- **Python 3.11+.** Build/test ONLY in the project venv: `.venv\Scripts\python.exe -m pytest` (never global python).
- **24/7 / no-crash:** no request — however malformed or hostile — may take down the process. Every unhandled exception returns the uniform envelope with code `internal_error` (HTTP 500), never a stack trace.
- **No hardcoded thresholds.** Detection windows/limits live in the `settings` table (`db.get_setting`). Connection-level infra values (`db_busy_timeout_ms`) live in `app/config.py` `Settings` (env-overridable) because they must be applied before the settings table is readable.
- **Graceful degradation:** auth/validation MUST keep working even if detection, audit, or notification code raises. Non-critical work is wrapped so its failure never breaks the request.
- **Uniform envelope** for all JSON endpoints: `{ "ok": bool, "code": str, "data": object|null, "message": str }`. The ONE exception is `GET /files/...` success, which returns raw decrypted bytes; its ERROR paths still use the envelope.
- **Coarse error codes:** existing (`ok`, `invalid_request`, `auth_failed`, `expired`, `hwid_mismatch`, `rate_limited`, `banned`, `cooldown`) plus new `internal_error`, `not_found`, `unavailable`.
- **Crypto:** payloads encrypted with AES-256-GCM; key = `sha256(b"keyauth-payload-key:" + SERVER_SECRET)`; random 12-byte nonce per payload; raw payload never stored unencrypted.
- **All times Unix seconds (int).** All SQL parameterized. Commit after every task.
- Spec: `docs/superpowers/specs/2026-06-29-license-key-server-design.md`. Phase 1 plan: `docs/superpowers/plans/2026-06-29-license-server-phase1-foundation.md`.
- **License-key correctness ("ไม่เอ๋อ"):** validation must be deterministic — no false accept, no false reject. Edge cases (expiry boundary, banned, HWID reset→rebind, clock skew, concurrent activation) are explicitly tested.

---

### Task 1: DB optimization — WAL + pragmas + busy_timeout

**Files:**
- Modify: `app/config.py` (add `db_busy_timeout_ms`)
- Modify: `app/db.py` (connection pragmas + WAL on init)
- Test: `tests/test_db_pragmas.py`

**Interfaces:**
- Consumes: `app.config.settings`.
- Produces: every `db()` connection runs with `foreign_keys=ON`, `busy_timeout=settings.db_busy_timeout_ms`, `synchronous=NORMAL`, `temp_store=MEMORY`, `cache_size=-8000`, `mmap_size=268435456`; `init_db()` sets `journal_mode=WAL` once.

- [ ] **Step 1: Add config value** — in `app/config.py` `Settings`, add field `db_busy_timeout_ms: int = 5000`.

- [ ] **Step 2: Write failing test `tests/test_db_pragmas.py`**

```python
from app import db


def test_connection_pragmas_applied():
    with db.db() as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 1
        assert conn.execute("PRAGMA synchronous").fetchone()[0] in (1, 2)  # NORMAL=1


def test_journal_mode_is_wal():
    with db.db() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_db_pragmas.py -q`
Expected: FAIL (journal_mode is `memory`/`delete`, not `wal`).

- [ ] **Step 4: Apply pragmas in `app/db.py`**

In the `db()` context manager, immediately after `conn.row_factory = sqlite3.Row`, replace the single `PRAGMA foreign_keys=ON` line with:

```python
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={settings.db_busy_timeout_ms}")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-8000")
    conn.execute("PRAGMA mmap_size=268435456")
```

In `init_db()`, before `conn.executescript(SCHEMA)`, add:

```python
        conn.execute("PRAGMA journal_mode=WAL")
```

Add `from .config import settings` if not already imported at top (it is — `settings` and `SETTINGS_DEFAULTS` are imported).

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_db_pragmas.py -q`
Expected: PASS.

- [ ] **Step 6: Ignore WAL sidecar files** — append to `.gitignore`: `*.db-wal` and `*.db-shm`.

- [ ] **Step 7: Run full suite + commit**

Run: `.venv/Scripts/python.exe -m pytest -q` (all pass)
```bash
git add app/config.py app/db.py tests/test_db_pragmas.py .gitignore
git commit -m "perf: WAL + tuned SQLite pragmas + busy_timeout"
```

---

### Task 2: Catch-all exception handler + DB-backed readiness

**Files:**
- Modify: `app/main.py` (generic Exception handler)
- Modify: `app/routers/client.py` (`/meta/health` does a DB check)
- Test: `tests/test_reliability_handlers.py`

**Interfaces:**
- Produces: any unhandled exception → `JSONResponse(500, envelope(False,"internal_error",None,"internal error"))`. `GET /api/v1/meta/health` runs `SELECT 1`; returns `ok_env({"status":"alive"})` or `ApiError(503,"unavailable")`.

- [ ] **Step 1: Write failing test `tests/test_reliability_handlers.py`**

```python
from fastapi.testclient import TestClient
from app.main import create_app


def test_health_checks_db():
    client = TestClient(create_app())
    r = client.get("/api/v1/meta/health")
    assert r.status_code == 200 and r.json()["data"]["status"] == "alive"


def test_unhandled_exception_returns_envelope():
    app = create_app()

    @app.get("/api/v1/_boom")
    def _boom():
        raise RuntimeError("kaboom")

    # raise_server_exceptions=False so the handler's response is returned, not re-raised
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/api/v1/_boom")
    assert r.status_code == 500
    body = r.json()
    assert body["ok"] is False and body["code"] == "internal_error"
    assert "kaboom" not in body["message"]  # no stack/detail leak
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_reliability_handlers.py -q`
Expected: FAIL (no `/api/v1/_boom` handler returns envelope; default 500).

- [ ] **Step 3: Add the generic handler in `app/main.py`**

Inside `create_app()`, after the `RequestValidationError` handler, add:

```python
    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception):
        # 24/7: no request may crash the process; never leak internals.
        return JSONResponse(
            status_code=500,
            content=envelope(False, "internal_error", None, "internal error"),
        )
```

- [ ] **Step 4: Make `/meta/health` touch the DB in `app/routers/client.py`**

Replace the existing `health()` route with:

```python
@router.get("/meta/health")
def health():
    try:
        with db.db() as conn:
            conn.execute("SELECT 1")
    except Exception:
        raise ApiError(503, "unavailable", "database not ready")
    return ok_env({"status": "alive"})
```

(`db` and `ApiError` are already imported in client.py.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_reliability_handlers.py -q`
Expected: PASS.

- [ ] **Step 6: Run full suite + commit**

```bash
git add app/main.py app/routers/client.py tests/test_reliability_handlers.py
git commit -m "feat: catch-all internal_error handler + DB-backed readiness check"
```

---

### Task 3: Bounded memory — rate-limiter sweep + ephemeral pruning

**Files:**
- Modify: `app/ratelimit.py` (add `sweep`)
- Modify: `app/routers/client.py` (add `_prune_ephemeral`, call in handshake)
- Test: `tests/test_pruning.py`

**Interfaces:**
- Produces:
  - `RateLimiter.sweep(now: int, max_window: int) -> None` — drops buckets whose newest entry is older than `now - max_window`.
  - `_prune_ephemeral(conn, now)` in client.py — deletes expired `challenges` (`expires_at < now`), old `used_nonces` (`seen_at < now - nonce_prune_seconds`), and old `access_events` (`ts < now - clone_ip_window_seconds`); also calls `limiter.sweep`. Called once at the start of `handshake`.

- [ ] **Step 1: Write failing test `tests/test_pruning.py`**

```python
from app.ratelimit import RateLimiter


def test_sweep_drops_idle_buckets():
    rl = RateLimiter()
    rl.allow("ip:1", limit=5, window=60, now=1000)
    assert "ip:1" in rl._hits
    rl.sweep(now=2000, max_window=60)  # 2000-60=1940 > 1000 -> idle
    assert "ip:1" not in rl._hits


def test_sweep_keeps_active_buckets():
    rl = RateLimiter()
    rl.allow("ip:1", limit=5, window=60, now=1000)
    rl.sweep(now=1030, max_window=60)  # entry at 1000 still within window
    assert "ip:1" in rl._hits
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_pruning.py -q`
Expected: FAIL (`AttributeError: ... 'sweep'`).

- [ ] **Step 3: Add `sweep` to `app/ratelimit.py`**

```python
    def sweep(self, now: int, max_window: int) -> None:
        cutoff = now - max_window
        for bucket in list(self._hits.keys()):
            q = self._hits[bucket]
            while q and q[0] <= cutoff:
                q.popleft()
            if not q:
                del self._hits[bucket]
```

- [ ] **Step 4: Scope note (no code in this step)**

This task adds ONLY `RateLimiter.sweep`. The DB-level pruning helper `_prune_ephemeral` (which deletes expired challenges, old nonces, and old `access_events`, and calls `limiter.sweep`) is added in **Task 7**, because it depends on the `access_events` table and the `clone_ip_window_seconds` setting that Task 7 creates. Do not add `_prune_ephemeral` here.

- [ ] **Step 5: Run tests + commit (sweep only)**

Run: `.venv/Scripts/python.exe -m pytest tests/test_pruning.py -q` (PASS)
Run: `.venv/Scripts/python.exe -m pytest -q` (all pass)
```bash
git add app/ratelimit.py tests/test_pruning.py
git commit -m "perf: rate-limiter idle-bucket sweep (bounded memory)"
```

---

### Task 4: Payload crypto module (AES-256-GCM) + cryptography dep

**Files:**
- Modify: `requirements.txt` (add `cryptography`)
- Create: `app/payload_crypto.py`
- Test: `tests/test_payload_crypto.py`

**Interfaces:**
- Produces:
  - `encrypt_payload(plaintext: bytes) -> tuple[bytes, bytes]` returns `(ciphertext, nonce)`.
  - `decrypt_payload(ciphertext: bytes, nonce: bytes) -> bytes`.
  - Key derived from `settings.server_secret`; AES-256-GCM.

- [ ] **Step 1: Add dependency** — append to `requirements.txt`: `cryptography==42.0.8`. Then install into the venv:

Run: `.venv/Scripts/python.exe -m pip install cryptography==42.0.8`

- [ ] **Step 2: Write failing test `tests/test_payload_crypto.py`**

```python
from app import payload_crypto as pc


def test_roundtrip():
    data = b"the real protected script bytes"
    ct, nonce = pc.encrypt_payload(data)
    assert ct != data
    assert pc.decrypt_payload(ct, nonce) == data


def test_unique_nonce_and_ciphertext():
    a_ct, a_n = pc.encrypt_payload(b"x")
    b_ct, b_n = pc.encrypt_payload(b"x")
    assert a_n != b_n and a_ct != b_ct  # random nonce per call


def test_tamper_detected():
    import pytest
    ct, nonce = pc.encrypt_payload(b"secret")
    with pytest.raises(Exception):
        pc.decrypt_payload(ct[:-1] + bytes([ct[-1] ^ 1]), nonce)  # GCM auth fails
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_payload_crypto.py -q`
Expected: FAIL (`ModuleNotFoundError: app.payload_crypto`).

- [ ] **Step 4: Implement `app/payload_crypto.py`**

```python
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


def _key() -> bytes:
    return hashlib.sha256(b"keyauth-payload-key:" + settings.server_secret.encode("utf-8")).digest()


def encrypt_payload(plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_payload(ciphertext: bytes, nonce: bytes) -> bytes:
    return AESGCM(_key()).decrypt(nonce, ciphertext, None)
```

- [ ] **Step 5: Run tests + commit**

Run: `.venv/Scripts/python.exe -m pytest tests/test_payload_crypto.py -q` (PASS)
```bash
git add requirements.txt app/payload_crypto.py tests/test_payload_crypto.py
git commit -m "feat: AES-256-GCM payload crypto (key from SERVER_SECRET)"
```

---

### Task 5: Payload service + `upload-payload` CLI

**Files:**
- Create: `app/services/payload.py`
- Modify: `app/cli.py` (add `upload-payload` subcommand + `cmd_upload_payload`)
- Test: `tests/test_payload_service.py`

**Interfaces:**
- Consumes: `app.payload_crypto`, `app.db`, `app.services.license.get_product`.
- Produces:
  - `upsert_payload(conn, product_id: int, resource_slug: str, plaintext: bytes) -> None` (encrypts then INSERT/ON CONFLICT update).
  - `get_payload(conn, product_id: int, resource_slug: str) -> sqlite3.Row | None`.
  - CLI `cmd_upload_payload(product: str, resource: str, path: str) -> int` (returns byte count); subcommand `upload-payload --product --resource --file`.

- [ ] **Step 1: Write failing test `tests/test_payload_service.py`**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_payload_service.py -q`
Expected: FAIL (`ModuleNotFoundError: app.services.payload`).

- [ ] **Step 3: Implement `app/services/payload.py`**

```python
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
```

- [ ] **Step 4: Add CLI in `app/cli.py`**

Add the programmatic function:

```python
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
```

In `main(...)`, register the subcommand (after `create-key`):

```python
    up = sub.add_parser("upload-payload")
    up.add_argument("--product", required=True)
    up.add_argument("--resource", required=True)
    up.add_argument("--file", required=True)
```

And in the dispatch chain:

```python
    elif args.cmd == "upload-payload":
        n = cmd_upload_payload(args.product, args.resource, args.file)
        print(f"uploaded {n} bytes to {args.product}/{args.resource}")
```

- [ ] **Step 5: Run tests + commit**

Run: `.venv/Scripts/python.exe -m pytest tests/test_payload_service.py -q` (PASS)
Run: `.venv/Scripts/python.exe -m pytest -q` (all pass)
```bash
git add app/services/payload.py app/cli.py tests/test_payload_service.py
git commit -m "feat: payload service (encrypted upsert) + upload-payload CLI"
```

---

### Task 6: Gated `GET /files/{product}/{resource}` endpoint

**Files:**
- Modify: `app/routers/client.py`
- Test: `tests/test_gated_payload.py`

**Interfaces:**
- Consumes: `_authed_session`, `app.services.payload.get_payload`, `app.payload_crypto.decrypt_payload`, `lic.is_expired`, `lic.audit`.
- Produces: `GET /api/v1/files/{product}/{resource}` → `fastapi.responses.Response(content=plaintext, media_type="application/octet-stream")` on success; ERROR paths raise `ApiError` (envelope). Rejects: no session (401), wrong product for the key (403 `auth_failed`), banned (403), expired (403, persists status), missing resource (404 `not_found`).

- [ ] **Step 1: Write failing test `tests/test_gated_payload.py`**

```python
import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.services import payload as pl
from app.ratelimit import limiter


def _setup_key_and_payload(product="manager", resource="main.lua", body=b"SECRET-SCRIPT"):
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, product, "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        pl.upsert_payload(conn, p["id"], resource, body)
        secret = p["app_secret"]
    return secret, raw


def _token(client, secret, raw, product="manager", hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, product, raw, hwid, nonce, ts)
    hs = client.post("/api/v1/auth/handshake", json={
        "product": product, "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}).json()
    cid, sn = hs["data"]["challenge_id"], hs["data"]["server_nonce"]
    ts2 = int(time.time()); ans = security.sign(secret, cid, sn, raw, hwid, ts2)
    return client.post("/api/v1/auth/verify", json={
        "challenge_id": cid, "key": raw, "hwid": hwid, "ts": ts2, "answer_sig": ans}).json()["data"]["token"]


def test_payload_requires_session():
    _setup_key_and_payload()
    client = TestClient(create_app())
    assert client.get("/api/v1/files/manager/main.lua").status_code == 401


def test_payload_delivered_to_valid_session():
    secret, raw = _setup_key_and_payload()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    r = client.get("/api/v1/files/manager/main.lua", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.content == b"SECRET-SCRIPT"


def test_wrong_product_rejected():
    secret, raw = _setup_key_and_payload()
    client = TestClient(create_app())
    with db.db() as conn:
        p2 = lic.create_product(conn, "other", "Other", "OTHER")
        pl.upsert_payload(conn, p2["id"], "main.lua", b"OTHER-SECRET")
    tok = _token(client, secret, raw)  # key is for 'manager'
    r = client.get("/api/v1/files/other/main.lua", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_missing_resource_404():
    secret, raw = _setup_key_and_payload()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    r = client.get("/api/v1/files/manager/nope.lua", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 404 and r.json()["code"] == "not_found"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_gated_payload.py -q`
Expected: FAIL (404 route missing).

- [ ] **Step 3: Add the route to `app/routers/client.py`**

Add imports at top (merge): `from fastapi.responses import Response`, `from .. import payload_crypto`, `from ..services import payload as pl`.

```python
@router.get("/files/{product}/{resource}")
def get_file(product: str, resource: str, request: Request):
    with db.db() as conn:
        sess = _authed_session(conn, request)
        k = conn.execute("SELECT * FROM license_keys WHERE id=?", (sess["key_id"],)).fetchone()
        prod = conn.execute("SELECT * FROM products WHERE id=?", (k["product_id"],)).fetchone()
        if prod is None or prod["slug"] != product:
            raise ApiError(403, "auth_failed", "key not valid for this product")
        if k["status"] == "banned":
            raise ApiError(403, "banned", "key banned")
        if lic.is_expired(k, int(time.time())):
            conn.execute("UPDATE license_keys SET status='expired' WHERE id=?", (k["id"],))
            raise ApiError(403, "expired", "license expired")
        row = pl.get_payload(conn, prod["id"], resource)
        if row is None:
            raise ApiError(404, "not_found", "resource not found")
        plaintext = payload_crypto.decrypt_payload(row["ciphertext"], row["nonce"])
        lic.audit(conn, "payload_fetch", key_id=k["id"], hwid=sess["hwid"], ip=_client_ip(request),
                  detail={"resource": resource})
    return Response(content=plaintext, media_type="application/octet-stream")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_gated_payload.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Run full suite + commit**

```bash
git add app/routers/client.py tests/test_gated_payload.py
git commit -m "feat: gated encrypted payload delivery (the anti-crack endpoint)"
```

---

### Task 7: `access_events` table + IP plumbing + recording + ephemeral prune wiring

**Files:**
- Modify: `app/config.py` (`trust_proxy`)
- Modify: `app/db.py` (`access_events` table + index; new settings defaults)
- Modify: `app/routers/client.py` (`_client_ip` XFF; `record_access`; wire `_prune_ephemeral` into handshake; ip_change logging on heartbeat)
- Test: `tests/test_access_events.py`

**Interfaces:**
- Consumes: `db.get_setting`.
- Produces:
  - `access_events(id, key_id, ip, hwid, ts, kind)` table + index `(key_id, ts)`.
  - `SETTINGS_DEFAULTS` gains: `clone_ip_window_seconds=3600`, `clone_max_ips=3`, `clone_concurrent_window_seconds=120`, `clone_flag_cooldown_seconds=600`.
  - `Settings.trust_proxy: bool = False`.
  - `_client_ip(request)` returns leftmost `X-Forwarded-For` hop when `settings.trust_proxy` else `request.client.host`.
  - `record_access(conn, key_id, ip, hwid, kind)` inserts an event.
  - `_prune_ephemeral` (defined in Task 3) now called at start of `handshake`; its `access_events` DELETE is active.

- [ ] **Step 1: Add config + settings + schema**

In `app/config.py` `Settings`, add `trust_proxy: bool = False`.

In `app/config.py` `SETTINGS_DEFAULTS`, add the four keys above.

In `app/db.py` `SCHEMA`, add (before the index section):

```sql
CREATE TABLE IF NOT EXISTS access_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL REFERENCES license_keys(id),
    ip TEXT NOT NULL,
    hwid TEXT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL
);
```
and add index: `CREATE INDEX IF NOT EXISTS idx_access_key_ts ON access_events(key_id, ts);`

- [ ] **Step 2: Write failing test `tests/test_access_events.py`**

```python
import time
from types import SimpleNamespace
from app import db
from app.routers import client as c
from app.config import settings
from app.services import license as lic


def _req(ip, xff=None):
    headers = {}
    if xff:
        headers["X-Forwarded-For"] = xff
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers=headers)


def test_client_ip_direct_vs_proxy():
    settings.trust_proxy = False
    assert c._client_ip(_req("1.2.3.4", xff="9.9.9.9, 8.8.8.8")) == "1.2.3.4"
    settings.trust_proxy = True
    try:
        assert c._client_ip(_req("1.2.3.4", xff="9.9.9.9, 8.8.8.8")) == "9.9.9.9"
    finally:
        settings.trust_proxy = False


def test_record_access_inserts():
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        k = lic.get_key_by_raw(conn, raw)
        c.record_access(conn, k["id"], "1.2.3.4", "HW1", "auth")
        n = conn.execute("SELECT COUNT(*) n FROM access_events WHERE key_id=?", (k["id"],)).fetchone()["n"]
    assert n == 1
```

Note: `request.headers` in FastAPI is case-insensitive; `_client_ip` must read it via `.get("X-Forwarded-For")` (Starlette headers are case-insensitive, and the test's plain dict uses that exact key).

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_access_events.py -q`
Expected: FAIL (`record_access` missing; XFF not honored).

- [ ] **Step 4: Update `_client_ip` and add `record_access` in `app/routers/client.py`**

Replace `_client_ip` with:

```python
def _client_ip(request: Request) -> str:
    if settings.trust_proxy:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"
```

Add `from ..config import settings` to the imports (merge). Add:

```python
def record_access(conn, key_id, ip, hwid, kind) -> None:
    conn.execute(
        "INSERT INTO access_events(key_id, ip, hwid, ts, kind) VALUES (?,?,?,?,?)",
        (key_id, ip, hwid, int(time.time()), kind),
    )
```

- [ ] **Step 5: Add `_prune_ephemeral`, wire it into handshake, and record access in verify/heartbeat**

Add this helper to `app/routers/client.py` (near `_consume_nonce`) — it is defined HERE in Task 7 (Task 3 only added `RateLimiter.sweep`):

```python
def _prune_ephemeral(conn, now: int) -> None:
    # Bounded growth for 24/7 uptime. Cheap, indexed DELETEs.
    nonce_age = db.get_setting(conn, "nonce_prune_seconds")
    ev_age = db.get_setting(conn, "clone_ip_window_seconds")
    conn.execute("DELETE FROM challenges WHERE expires_at < ?", (now,))
    conn.execute("DELETE FROM used_nonces WHERE seen_at < ?", (now - nonce_age,))
    conn.execute("DELETE FROM access_events WHERE ts < ?", (now - ev_age,))
    limiter.sweep(now, max_window=max(ev_age, 3600))
```

Add as the FIRST statement inside handshake's `with db.db() as conn:` block:

```python
        _prune_ephemeral(conn, int(time.time()))
```

In `verify`, right after the successful session INSERT + `lic.audit(... "login" ...)`, add:

```python
        record_access(conn, key_row["id"], ip, req.hwid, "auth")
```

In `heartbeat`, after `_authed_session` returns `sess` and the key is loaded, before the return, add (records the heartbeat + flags an IP change without blocking):

```python
        if sess["ip"] != _client_ip(request):
            lic.audit(conn, "ip_change", key_id=k["id"], hwid=sess["hwid"], ip=_client_ip(request),
                      detail={"session_ip": sess["ip"]})
        record_access(conn, k["id"], _client_ip(request), sess["hwid"], "heartbeat")
```

- [ ] **Step 6: Run tests + commit**

Run: `.venv/Scripts/python.exe -m pytest tests/test_access_events.py -q` (PASS)
Run: `.venv/Scripts/python.exe -m pytest -q` (all pass)
```bash
git add app/config.py app/db.py app/routers/client.py tests/test_access_events.py
git commit -m "feat: access_events log, X-Forwarded-For support, access recording + prune wiring"
```

---

### Task 8: Clone detection (IP-velocity + concurrent-use) — flag only

**Files:**
- Create: `app/services/detection.py`
- Modify: `app/routers/client.py` (call detection after recording access in verify + heartbeat, wrapped for graceful degradation)
- Test: `tests/test_detection.py`

**Interfaces:**
- Consumes: `db.get_setting`, `lic.audit`, `access_events`.
- Produces: `check_clone(conn, key_id: int, now: int) -> bool` — returns True if a `clone_suspected` flag was written this call. Logic: count distinct IPs for `key_id` within `clone_ip_window_seconds`; if `> clone_max_ips` OR (≥2 distinct IPs within `clone_concurrent_window_seconds`) → write `clone_suspected` audit (severity high) unless one was written within `clone_flag_cooldown_seconds`.

- [ ] **Step 1: Write failing test `tests/test_detection.py`**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_detection.py -q`
Expected: FAIL (`ModuleNotFoundError: app.services.detection`).

- [ ] **Step 3: Implement `app/services/detection.py`**

```python
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
```

- [ ] **Step 4: Wire detection into verify + heartbeat (graceful degradation)**

In `app/routers/client.py`, add import: `from ..services import detection as det`.

In `verify`, immediately after the `record_access(...)` line, add a wrapped call so detection failure never breaks auth:

```python
        try:
            det.check_clone(conn, key_row["id"], now)
        except Exception:
            pass
```

In `heartbeat`, after the `record_access(...)` line, add:

```python
        try:
            det.check_clone(conn, k["id"], int(time.time()))
        except Exception:
            pass
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_detection.py -q` (3 PASS)
Run: `.venv/Scripts/python.exe -m pytest -q` (all pass)

- [ ] **Step 6: Commit**

```bash
git add app/services/detection.py app/routers/client.py tests/test_detection.py
git commit -m "feat: server-side clone detection (IP-velocity + concurrent), flag-only with cooldown"
```

---

### Task 9: License-key correctness — fail-fast banned + edge-case suite ("ไม่เอ๋อ")

**Files:**
- Modify: `app/routers/client.py` (reject banned at handshake)
- Test: `tests/test_key_edges.py`

**Interfaces:**
- Produces: handshake rejects a `banned` key early with `ApiError(403, "banned")` (before issuing a challenge). New edge tests proving deterministic validation.

- [ ] **Step 1: Write failing test `tests/test_key_edges.py`**

```python
import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap(duration=3600):
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], duration)
        secret = p["app_secret"]
    return secret, raw


def _handshake(client, secret, raw, hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig})


def test_banned_key_rejected_at_handshake():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    with db.db() as conn:
        conn.execute("UPDATE license_keys SET status='banned'")
    r = _handshake(client, secret, raw)
    assert r.status_code == 403 and r.json()["code"] == "banned"


def test_expiry_exact_boundary_is_expired():
    # is_expired uses now >= expires_at, so exactly-at-expiry counts as expired
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 100)
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HW1", 1000)  # expires_at = 1100
        row = lic.get_key_by_raw(conn, raw)
    assert lic.is_expired(row, 1100) is True
    assert lic.is_expired(row, 1099) is False


def test_reset_then_rebind_new_hwid_succeeds():
    secret, raw = _bootstrap()
    client = TestClient(create_app())

    def full_auth(hwid):
        hs = _handshake(client, secret, raw, hwid=hwid).json()["data"]
        ts = int(time.time()); ans = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, hwid, ts)
        return client.post("/api/v1/auth/verify", json={
            "challenge_id": hs["challenge_id"], "key": raw, "hwid": hwid, "ts": ts, "answer_sig": ans})

    assert full_auth("HW1").json()["ok"] is True
    # reset hwid directly (cooldown bypass via DB for this unit test)
    with db.db() as conn:
        conn.execute("UPDATE license_keys SET hwid=NULL")
    assert full_auth("HW2").json()["ok"] is True  # re-binds to new machine
    with db.db() as conn:
        assert lic.get_key_by_raw(conn, raw)["hwid"] == "HW2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_key_edges.py -q`
Expected: FAIL (`test_banned_key_rejected_at_handshake` — handshake currently issues a challenge for a banned key).

- [ ] **Step 3: Add fail-fast banned check in handshake**

In `app/routers/client.py` `handshake`, after the `key_row = lic.get_key_by_raw(conn, req.key)` line and its `None` check, add:

```python
        if key_row["status"] == "banned":
            raise ApiError(403, "banned", "key banned")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_key_edges.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Run full suite + commit**

```bash
git add app/routers/client.py tests/test_key_edges.py
git commit -m "fix: fail-fast banned at handshake + key-validation edge-case suite"
```

---

### Task 10: `reset-hwid` operator CLI + detection-safe reset

**Files:**
- Modify: `app/cli.py` (`reset-hwid` subcommand + `cmd_reset_hwid`)
- Test: `tests/test_reset_hwid_cli.py`

**Interfaces:**
- Produces: `cmd_reset_hwid(key: str) -> bool` — force-clears `hwid` (NULL), increments `hwid_reset_count`, sets `last_hwid_reset_at=now`, revokes live sessions for the key, audits `hwid_reset_admin`. No cooldown (operator action). Subcommand `reset-hwid --key <rawkey>`. Returns False if key unknown.

- [ ] **Step 1: Write failing test `tests/test_reset_hwid_cli.py`**

```python
import time
from app import db, cli
from app.services import license as lic


def test_cmd_reset_hwid_clears_and_revokes():
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HW1", int(time.time()))
        conn.execute("INSERT INTO sessions(token_hash, key_id, hwid, ip, issued_at, expires_at, revoked) "
                     "VALUES ('th', ?, 'HW1', '1.1.1.1', ?, ?, 0)",
                     (lic.get_key_by_raw(conn, raw)["id"], int(time.time()), int(time.time()) + 3600))
    assert cli.cmd_reset_hwid(key=raw) is True
    with db.db() as conn:
        k = lic.get_key_by_raw(conn, raw)
        assert k["hwid"] is None and k["hwid_reset_count"] == 1
        live = conn.execute("SELECT COUNT(*) c FROM sessions WHERE revoked=0").fetchone()["c"]
    assert live == 0


def test_cmd_reset_hwid_unknown_key():
    assert cli.cmd_reset_hwid(key="MASTERP-AAAAA-BBBBB-CCCCC-DDDDD") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_reset_hwid_cli.py -q`
Expected: FAIL (`cmd_reset_hwid` missing).

- [ ] **Step 3: Implement in `app/cli.py`**

```python
def cmd_reset_hwid(key) -> bool:
    db.init_db()
    with db.db() as conn:
        k = lic.get_key_by_raw(conn, key)
        if k is None:
            return False
        now = int(time.time())
        conn.execute("UPDATE license_keys SET hwid=NULL, hwid_reset_count=hwid_reset_count+1, "
                     "last_hwid_reset_at=? WHERE id=?", (now, k["id"]))
        conn.execute("UPDATE sessions SET revoked=1 WHERE key_id=? AND revoked=0", (k["id"],))
        lic.audit(conn, "hwid_reset_admin", key_id=k["id"])
    return True
```

In `main(...)` add subcommand + dispatch:

```python
    rh = sub.add_parser("reset-hwid")
    rh.add_argument("--key", required=True)
```
```python
    elif args.cmd == "reset-hwid":
        print("reset" if cmd_reset_hwid(args.key) else "unknown key")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_reset_hwid_cli.py -q`
Expected: PASS (2 tests). The next `auth/verify` with a new HWID re-binds via the existing `hwid is None` branch (proven in Task 9).

- [ ] **Step 5: Run full suite + commit**

```bash
git add app/cli.py tests/test_reset_hwid_cli.py
git commit -m "feat: operator reset-hwid CLI (force-reset, no cooldown, revokes sessions)"
```

---

### Task 11: Docker deployment (24/7) — Dockerfile + compose + docs

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `.dockerignore`
- Modify: `README.md` (deployment section)
- Test: none (config artifacts; verified by build instructions)

**Interfaces:**
- Produces: a container running `uvicorn app.main:app`, with `restart: always`, a healthcheck hitting `/api/v1/meta/health`, and a named volume for the SQLite file (+ WAL sidecars) so data persists across restarts.

- [ ] **Step 1: Create `Dockerfile`**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DB_PATH=/data/keyauth.db

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# SQLite lives on a mounted volume so it survives container restarts.
VOLUME ["/data"]

EXPOSE 8000

# Single robust worker; the orchestrator restarts on crash.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```

- [ ] **Step 2: Create `.dockerignore`**

```
.git
.venv
venv
__pycache__
*.pyc
*.db
*.db-wal
*.db-shm
.env
.superpowers
docs
tests
```

- [ ] **Step 3: Create `docker-compose.yml`**

```yaml
services:
  keyauth:
    build: .
    restart: always
    env_file: .env
    environment:
      DB_PATH: /data/keyauth.db
    volumes:
      - keyauth-data:/data
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/meta/health').status==200 else 1)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  keyauth-data:
```

- [ ] **Step 4: Add a Deployment section to `README.md`**

Append:

```markdown
## Deployment (24/7, Docker)

Single robust instance with auto-restart. Run behind nginx/Caddy with TLS terminated.

```bash
cp .env.example .env   # set SERVER_SECRET, ADMIN_PASSWORD, etc.
docker compose up -d --build
docker compose ps      # healthcheck should show "healthy"
docker compose logs -f keyauth
```

- The SQLite database (and its WAL sidecars) live in the `keyauth-data` volume and survive restarts/redeploys.
- `restart: always` + the healthcheck mean the container self-heals on crash.
- **Backup:** `docker compose exec keyauth sh -c "sqlite3 /data/keyauth.db '.backup /data/backup.db'"` (or stop briefly and copy `/data`).
- **Scale-out (future):** for true multi-instance HA, migrate SQLite → PostgreSQL and move rate-limit/nonce/session state to Redis; then run N replicas behind the proxy.
```

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore docker-compose.yml README.md
git commit -m "feat: Docker deployment (restart:always + healthcheck + persistent volume)"
```

---

### Task 12: Reliability tests — no-crash under hostile/concurrent input

**Files:**
- Test: `tests/test_reliability.py`

**Interfaces:**
- Consumes: the full app. Proves the server returns a coded envelope (never crashes / never leaks) for malformed, oversized, and concurrent input.

- [ ] **Step 1: Write `tests/test_reliability.py`**

```python
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def test_malformed_json_body_returns_envelope():
    client = TestClient(create_app())
    r = client.post("/api/v1/auth/handshake", json={"product": "x"})  # missing required fields
    assert r.status_code == 400
    assert r.json()["code"] == "invalid_request"


def test_oversized_field_does_not_crash():
    client = TestClient(create_app())
    huge = "A" * 2_000_000
    r = client.post("/api/v1/auth/handshake", json={
        "product": huge, "key": huge, "hwid": huge, "nonce": "n", "ts": int(time.time()), "sig": "x"})
    # Either rejected as bad product/sig or invalid — never a 500 crash.
    assert r.status_code in (400, 401, 429)
    assert r.json()["ok"] is False


def test_concurrent_handshakes_stay_consistent():
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "M", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        secret = p["app_secret"]
    client = TestClient(create_app())

    def one(i):
        ts = int(time.time()); nonce = f"n{i}"
        sig = security.sign(secret, "manager", raw, "HW1", nonce, ts)
        return client.post("/api/v1/auth/handshake", json={
            "product": "manager", "key": raw, "hwid": "HW1", "nonce": nonce, "ts": ts, "sig": sig}).status_code

    with ThreadPoolExecutor(max_workers=8) as ex:
        codes = list(ex.map(one, range(24)))
    # No 500s; each is either OK (200) or rate-limited (429) — never a crash.
    assert all(c in (200, 429) for c in codes)
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_reliability.py -q`
Expected: PASS (3 tests). If any returns 500, fix the offending endpoint (the catch-all handler should already prevent crashes; a 500 means a handler path needs hardening).

- [ ] **Step 3: Run full suite + commit**

Run: `.venv/Scripts/python.exe -m pytest -q` (all pass)
```bash
git add tests/test_reliability.py
git commit -m "test: reliability — malformed/oversized/concurrent input never crashes"
```

---

## Phase 2 Done — Definition of Done

- `.venv/Scripts/python.exe -m pytest -q` fully green.
- A product + key + encrypted payload can be created via CLI; a valid session pulls the payload via `/files`, and no-session / wrong-product / banned / expired / missing-resource are all rejected.
- Clone detection flags IP-velocity and concurrent-use into `audit_logs` (`clone_suspected`), thresholds tunable in `settings`, and detection failure never breaks auth.
- Operator can `reset-hwid` a key on demand; the next auth re-binds the new HWID.
- DB runs in WAL with busy_timeout; ephemeral tables and rate-limiter buckets are pruned/bounded.
- Any malformed/oversized/concurrent request returns a coded envelope — never a 500 crash or stack leak.
- `docker compose up -d --build` runs the server with auto-restart + healthcheck + persistent volume.

## Deferred to Phase 3
Admin web dashboard + admin REST API + Discord webhook alerts (fire on `clone_suspected`). Multi-instance HA (Postgres + Redis) remains a documented future path, not in scope.
