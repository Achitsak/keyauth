# License Server — Phase 1: Foundation & Core License Validation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working, hardened license server that validates subscription keys via a signed challenge-response flow, binds each key to one HWID, enforces one active session per key, and is fully configurable (no hardcoded thresholds).

**Architecture:** FastAPI app over stdlib `sqlite3` (no ORM, dependency-light). Clients are treated as hostile: every client request is HMAC-SHA256 signed with a per-product secret; replay is blocked by a single-use server challenge + nonce + timestamp window. A session token (stored hashed) gates everything after auth. All operational thresholds live in a `settings` DB table read at runtime.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, pydantic v2, pydantic-settings, argon2-cffi, httpx (tests), pytest, pytest-asyncio. SQLite via stdlib `sqlite3`. HMAC/hashing via stdlib `hmac`/`hashlib`/`secrets`.

## Global Constraints

- **Python 3.11+.** Type hints everywhere.
- **No exotic deps in the request/signing path** — signing is HMAC-SHA256 over a newline-joined field string, reproducible in Python/Go/Node with stdlib only.
- **No hardcoded thresholds.** Every TTL/cooldown/window/limit is read via `db.get_setting(...)`, which falls back to `SETTINGS_DEFAULTS`. Never inline a magic number for these.
- **Raw keys are never stored** — only `sha256(key)`. Session tokens never stored raw — only `sha256(token)`.
- **Uniform response envelope** for all client endpoints: `{ "ok": bool, "code": str, "data": object|null, "message": str }`.
- **Coarse error codes only:** `ok`, `invalid_request`, `auth_failed`, `expired`, `hwid_mismatch`, `rate_limited`, `banned`, `cooldown`.
- **Constant-time comparison** for all secret/hash/HMAC comparisons (`hmac.compare_digest`).
- **All times are Unix seconds (UTC), `int(time.time())`.**
- Commit after every task. Conventional-commit messages.
- Spec reference: `docs/superpowers/specs/2026-06-29-license-key-server-design.md`.

---

### Task 1: Project scaffold

**Files:**
- Create: `requirements.txt`
- Create: `pyproject.toml`
- Create: `app/__init__.py` (empty)
- Create: `tests/__init__.py` (empty)
- Create: `tests/test_smoke.py`

**Interfaces:**
- Consumes: nothing.
- Produces: an importable `app` package and a green `pytest` run.

- [ ] **Step 1: Create `requirements.txt`**

```
fastapi==0.111.0
uvicorn[standard]==0.30.1
pydantic==2.7.4
pydantic-settings==2.3.4
argon2-cffi==23.1.0
httpx==0.27.0
pytest==8.2.2
pytest-asyncio==0.23.7
```

- [ ] **Step 2: Create `pyproject.toml`** (pytest config)

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 3: Create empty `app/__init__.py` and `tests/__init__.py`**

(both empty files)

- [ ] **Step 4: Write smoke test `tests/test_smoke.py`**

```python
def test_imports():
    import app  # noqa: F401
    assert True
```

- [ ] **Step 5: Install and run**

Run: `pip install -r requirements.txt && pytest -q`
Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add requirements.txt pyproject.toml app tests
git commit -m "chore: project scaffold and pytest setup"
```

---

### Task 2: Configuration + settings defaults

**Files:**
- Create: `app/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces:
  - `settings: Settings` — pydantic-settings instance with: `db_path: str`, `server_secret: str`, `admin_username: str`, `admin_password: str`, `discord_webhook_url: str`, `environment: str`.
  - `SETTINGS_DEFAULTS: dict[str, int]` — runtime-tunable defaults: keys `auth_ts_window_seconds=30`, `challenge_ttl_seconds=60`, `session_ttl_seconds=3600`, `hwid_reset_cooldown_days=7`, `rate_limit_auth_per_min=10`, `nonce_prune_seconds=120`.

- [ ] **Step 1: Write failing test `tests/test_config.py`**

```python
from app.config import settings, SETTINGS_DEFAULTS

def test_settings_have_defaults():
    assert settings.db_path
    assert SETTINGS_DEFAULTS["auth_ts_window_seconds"] == 30
    assert SETTINGS_DEFAULTS["session_ttl_seconds"] == 3600
    assert SETTINGS_DEFAULTS["hwid_reset_cooldown_days"] == 7
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -q`
Expected: FAIL (`ModuleNotFoundError: app.config`).

- [ ] **Step 3: Implement `app/config.py`**

```python
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    db_path: str = "keyauth.db"
    server_secret: str = "dev-server-secret-change-me"
    admin_username: str = "admin"
    admin_password: str = "change-me-on-first-boot"
    discord_webhook_url: str = ""
    environment: str = "dev"


settings = Settings()

# Runtime-tunable defaults. Code reads these via db.get_setting(), which
# returns the DB row if present, else the value here. NEVER inline these numbers.
SETTINGS_DEFAULTS: dict[str, int] = {
    "auth_ts_window_seconds": 30,
    "challenge_ttl_seconds": 60,
    "session_ttl_seconds": 3600,
    "hwid_reset_cooldown_days": 7,
    "rate_limit_auth_per_min": 10,
    "nonce_prune_seconds": 120,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/config.py tests/test_config.py
git commit -m "feat: config and runtime settings defaults"
```

---

### Task 3: Database layer + schema + settings accessors

**Files:**
- Create: `app/db.py`
- Test: `tests/conftest.py`
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: `app.config.settings`, `SETTINGS_DEFAULTS`.
- Produces:
  - `set_db_path(path: str) -> None`
  - `db()` — context manager yielding a `sqlite3.Connection` (Row factory, FK on, autocommit on clean exit).
  - `init_db() -> None` — creates all tables + seeds `settings` defaults.
  - `get_setting(conn, key: str) -> int` — DB value or `SETTINGS_DEFAULTS[key]`.
  - `set_setting(conn, key: str, value: int) -> None`.

- [ ] **Step 1: Write `tests/conftest.py`** (shared fixture: isolated temp DB per test)

```python
import pytest
from app import db


@pytest.fixture(autouse=True)
def temp_db(tmp_path):
    db.set_db_path(str(tmp_path / "test.db"))
    db.init_db()
    yield
```

- [ ] **Step 2: Write failing test `tests/test_db.py`**

```python
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_db.py -q`
Expected: FAIL (`ModuleNotFoundError: app.db`).

- [ ] **Step 4: Implement `app/db.py`**

```python
import contextlib
import sqlite3
import time

from .config import settings, SETTINGS_DEFAULTS

_DB_PATH = settings.db_path


def set_db_path(path: str) -> None:
    global _DB_PATH
    _DB_PATH = path


@contextlib.contextmanager
def db():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    app_secret TEXT NOT NULL,
    hwid_reset_cooldown_days INTEGER,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS license_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    product_id INTEGER NOT NULL REFERENCES products(id),
    duration_seconds INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'unused',
    hwid TEXT,
    hwid_set_at INTEGER,
    hwid_reset_count INTEGER NOT NULL DEFAULT 0,
    last_hwid_reset_at INTEGER,
    activated_at INTEGER,
    expires_at INTEGER,
    note TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    last_login_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    key_id INTEGER NOT NULL REFERENCES license_keys(id),
    hwid TEXT NOT NULL,
    ip TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    server_nonce TEXT NOT NULL,
    key_id INTEGER REFERENCES license_keys(id),
    hwid TEXT NOT NULL,
    ip TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS used_nonces (
    nonce TEXT PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    key_id INTEGER,
    hwid TEXT,
    ip TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    detail_json TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL REFERENCES products(id),
    resource_slug TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(product_id, resource_slug)
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
CREATE INDEX IF NOT EXISTS idx_challenges_exp ON challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_nonce_seen ON used_nonces(seen_at);
CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(key_id);
"""


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
        now = int(time.time())
        for key, value in SETTINGS_DEFAULTS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value, updated_at) VALUES (?,?,?)",
                (key, value, now),
            )


def get_setting(conn, key: str) -> int:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is not None:
        return int(row["value"])
    return SETTINGS_DEFAULTS[key]


def set_setting(conn, key: str, value: int) -> None:
    conn.execute(
        "INSERT INTO settings(key, value, updated_at) VALUES (?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, int(value), int(time.time())),
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_db.py -q`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add app/db.py tests/conftest.py tests/test_db.py
git commit -m "feat: sqlite schema, db context manager, settings accessors"
```

---

### Task 4: Security primitives

**Files:**
- Create: `app/security.py`
- Test: `tests/test_security.py`

**Interfaces:**
- Produces:
  - `generate_key(prefix: str) -> str` — `f"{prefix}-XXXXX-XXXXX-XXXXX-XXXXX"`, Crockford base32, ~100 bits.
  - `hash_key(raw_key: str) -> str` — sha256 hex.
  - `key_prefix_display(raw_key: str) -> str` — first 12 chars (for search/display).
  - `hash_password(pw: str) -> str` / `verify_password(pw: str, hashed: str) -> bool` — argon2.
  - `new_token() -> str` / `hash_token(token: str) -> str` — 32-byte url-safe token + sha256.
  - `new_nonce() -> str` — 16-byte url-safe.
  - `sign(secret: str, *fields) -> str` — `HMAC_SHA256(secret, "\n".join(str(f) for f in fields))` hex.
  - `verify_sig(secret: str, sig: str, *fields) -> bool` — constant-time.

- [ ] **Step 1: Write failing test `tests/test_security.py`**

```python
from app import security as s


def test_generate_key_format():
    k = s.generate_key("MASTERP")
    parts = k.split("-")
    assert parts[0] == "MASTERP"
    assert len(parts) == 5
    assert all(len(p) == 5 for p in parts[1:])
    assert s.generate_key("MASTERP") != s.generate_key("MASTERP")


def test_hash_key_stable_and_hex():
    h = s.hash_key("MASTERP-AAAAA-BBBBB-CCCCC-DDDDD")
    assert h == s.hash_key("MASTERP-AAAAA-BBBBB-CCCCC-DDDDD")
    assert len(h) == 64


def test_password_roundtrip():
    h = s.hash_password("hunter2")
    assert s.verify_password("hunter2", h)
    assert not s.verify_password("wrong", h)


def test_sign_verify():
    sig = s.sign("secret", "a", "b", 123)
    assert s.verify_sig("secret", sig, "a", "b", 123)
    assert not s.verify_sig("secret", sig, "a", "b", 124)
    assert not s.verify_sig("other", sig, "a", "b", 123)


def test_token_and_nonce_unique():
    assert s.new_token() != s.new_token()
    assert s.new_nonce() != s.new_nonce()
    assert len(s.hash_token("x")) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_security.py -q`
Expected: FAIL (`ModuleNotFoundError: app.security`).

- [ ] **Step 3: Implement `app/security.py`**

```python
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # no I L O U
_ph = PasswordHasher()


def _group(n: int = 5) -> str:
    return "".join(secrets.choice(_CROCKFORD) for _ in range(n))


def generate_key(prefix: str) -> str:
    return f"{prefix}-{_group()}-{_group()}-{_group()}-{_group()}"


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def key_prefix_display(raw_key: str) -> str:
    return raw_key[:12]


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def _canonical(*fields) -> bytes:
    return "\n".join(str(f) for f in fields).encode("utf-8")


def sign(secret: str, *fields) -> str:
    return hmac.new(secret.encode("utf-8"), _canonical(*fields), hashlib.sha256).hexdigest()


def verify_sig(secret: str, sig: str, *fields) -> bool:
    expected = sign(secret, *fields)
    return hmac.compare_digest(expected, sig or "")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_security.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add app/security.py tests/test_security.py
git commit -m "feat: security primitives (keygen, hashing, hmac signing, tokens)"
```

---

### Task 5: Response envelope + request models

**Files:**
- Create: `app/envelope.py`
- Create: `app/models.py`
- Test: `tests/test_envelope.py`

**Interfaces:**
- Produces:
  - `envelope(ok: bool, code: str, data=None, message: str = "") -> dict` and `ok_env(data=None) -> dict`.
  - `class ApiError(Exception)` with `.status_code: int`, `.code: str`, `.message: str`.
  - Pydantic models: `HandshakeReq{product,key,hwid,nonce,ts,sig}`, `VerifyReq{challenge_id,key,hwid,ts,answer_sig}`, `HwidResetReq{product,key,hwid,nonce,ts,sig}`. All `ts: int`, all strings non-empty.

- [ ] **Step 1: Write failing test `tests/test_envelope.py`**

```python
from app.envelope import envelope, ok_env, ApiError


def test_envelope_shape():
    e = envelope(False, "auth_failed", message="nope")
    assert e == {"ok": False, "code": "auth_failed", "data": None, "message": "nope"}
    assert ok_env({"x": 1}) == {"ok": True, "code": "ok", "data": {"x": 1}, "message": ""}


def test_api_error_carries_fields():
    err = ApiError(401, "auth_failed", "bad")
    assert err.status_code == 401 and err.code == "auth_failed" and err.message == "bad"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_envelope.py -q`
Expected: FAIL (`ModuleNotFoundError: app.envelope`).

- [ ] **Step 3: Implement `app/envelope.py`**

```python
def envelope(ok: bool, code: str, data=None, message: str = "") -> dict:
    return {"ok": ok, "code": code, "data": data, "message": message}


def ok_env(data=None) -> dict:
    return envelope(True, "ok", data, "")


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
```

- [ ] **Step 4: Implement `app/models.py`**

```python
from pydantic import BaseModel, Field


class HandshakeReq(BaseModel):
    product: str = Field(min_length=1)
    key: str = Field(min_length=1)
    hwid: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ts: int
    sig: str = Field(min_length=1)


class VerifyReq(BaseModel):
    challenge_id: str = Field(min_length=1)
    key: str = Field(min_length=1)
    hwid: str = Field(min_length=1)
    ts: int
    answer_sig: str = Field(min_length=1)


class HwidResetReq(BaseModel):
    product: str = Field(min_length=1)
    key: str = Field(min_length=1)
    hwid: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ts: int
    sig: str = Field(min_length=1)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_envelope.py -q`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add app/envelope.py app/models.py tests/test_envelope.py
git commit -m "feat: response envelope, ApiError, request models"
```

---

### Task 6: License service — products, keys, activation, expiry

**Files:**
- Create: `app/services/__init__.py` (empty)
- Create: `app/services/license.py`
- Test: `tests/test_license_service.py`

**Interfaces:**
- Consumes: `app.db`, `app.security`.
- Produces (all take an open `conn` as first arg):
  - `create_product(conn, slug, name, key_prefix, cooldown_days=None) -> dict` (returns product row incl. generated `app_secret`).
  - `get_product(conn, slug) -> sqlite3.Row | None`.
  - `create_key(conn, product_id, duration_seconds, note="") -> str` (returns the raw key, stores hash).
  - `get_key_by_raw(conn, raw_key) -> sqlite3.Row | None`.
  - `is_expired(key_row, now: int) -> bool`.
  - `activate_if_new(conn, key_row, hwid, now) -> None` — on first use sets hwid/activated_at/expires_at, status `active`.
  - `audit(conn, event_type, key_id=None, hwid=None, ip=None, severity="info", detail=None) -> None`.

- [ ] **Step 1: Write failing test `tests/test_license_service.py`**

```python
import time
from app import db
from app.services import license as lic


def _setup():
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Masterp Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], duration_seconds=3600)
    return p, raw


def test_create_and_lookup_key():
    p, raw = _setup()
    with db.db() as conn:
        row = lic.get_key_by_raw(conn, raw)
        assert row["product_id"] == p["id"]
        assert row["status"] == "unused"


def test_activation_sets_expiry_and_hwid():
    p, raw = _setup()
    now = int(time.time())
    with db.db() as conn:
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HWID-1", now)
        row2 = lic.get_key_by_raw(conn, raw)
        assert row2["status"] == "active"
        assert row2["hwid"] == "HWID-1"
        assert row2["expires_at"] == now + 3600


def test_is_expired():
    p, raw = _setup()
    with db.db() as conn:
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HWID-1", 1000)
        row2 = lic.get_key_by_raw(conn, raw)
    assert lic.is_expired(row2, now=1000 + 3601)
    assert not lic.is_expired(row2, now=1000 + 10)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_license_service.py -q`
Expected: FAIL (`ModuleNotFoundError: app.services.license`).

- [ ] **Step 3: Implement `app/services/license.py`**

```python
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
    return get_product(conn, slug)


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
            "activated_at=?, expires_at=? WHERE id=?",
            (hwid, now, now, now + key_row["duration_seconds"], key_row["id"]),
        )


def audit(conn, event_type, key_id=None, hwid=None, ip=None, severity="info", detail=None):
    conn.execute(
        "INSERT INTO audit_logs(ts, event_type, key_id, hwid, ip, severity, detail_json) "
        "VALUES (?,?,?,?,?,?,?)",
        (int(time.time()), event_type, key_id, hwid, ip, severity,
         json.dumps(detail) if detail is not None else None),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_license_service.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add app/services tests/test_license_service.py
git commit -m "feat: license service (products, keys, activation, expiry, audit)"
```

---

### Task 7: In-memory rate limiter

**Files:**
- Create: `app/ratelimit.py`
- Test: `tests/test_ratelimit.py`

**Interfaces:**
- Produces:
  - `class RateLimiter` with `__init__(self)`, `allow(self, bucket: str, limit: int, window: int, now: int) -> bool`, `reset(self)`.
  - Module-level `limiter = RateLimiter()`.
- Note: per-process in-memory (sufficient for single-instance deploy; Phase 2 can swap to a shared store). Window is a sliding count.

- [ ] **Step 1: Write failing test `tests/test_ratelimit.py`**

```python
from app.ratelimit import RateLimiter


def test_allows_then_blocks_within_window():
    rl = RateLimiter()
    for i in range(3):
        assert rl.allow("ip:1", limit=3, window=60, now=1000 + i)
    assert not rl.allow("ip:1", limit=3, window=60, now=1001)


def test_window_rolls_off():
    rl = RateLimiter()
    assert rl.allow("ip:1", limit=1, window=60, now=1000)
    assert not rl.allow("ip:1", limit=1, window=60, now=1030)
    assert rl.allow("ip:1", limit=1, window=60, now=1061)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ratelimit.py -q`
Expected: FAIL (`ModuleNotFoundError: app.ratelimit`).

- [ ] **Step 3: Implement `app/ratelimit.py`**

```python
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, bucket: str, limit: int, window: int, now: int) -> bool:
        q = self._hits[bucket]
        cutoff = now - window
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def reset(self):
        self._hits.clear()


limiter = RateLimiter()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ratelimit.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add app/ratelimit.py tests/test_ratelimit.py
git commit -m "feat: sliding-window in-memory rate limiter"
```

---

### Task 8: App factory + meta endpoints (health, time)

**Files:**
- Create: `app/main.py`
- Test: `tests/test_meta.py`

**Interfaces:**
- Consumes: `app.db.init_db`, `app.envelope`.
- Produces:
  - `create_app() -> FastAPI` — registers an exception handler that renders `ApiError` as the envelope with its `status_code`, includes the client router, and calls `init_db()` on startup.
  - `app = create_app()`.
  - `GET /api/v1/meta/health` → `ok_env({"status":"alive"})`.
  - `GET /api/v1/meta/time` → `ok_env({"ts": <int unix>})`.
- Routers are added in later tasks via `app/routers/client.py`; this task creates that module with only the meta routes, expanded in Tasks 9–12.

- [ ] **Step 1: Write failing test `tests/test_meta.py`**

```python
from fastapi.testclient import TestClient
from app.main import create_app


def test_health_and_time():
    client = TestClient(create_app())
    r = client.get("/api/v1/meta/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["data"]["status"] == "alive"

    r2 = client.get("/api/v1/meta/time")
    assert r2.json()["data"]["ts"] > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_meta.py -q`
Expected: FAIL (`ModuleNotFoundError: app.main`).

- [ ] **Step 3: Create `app/routers/__init__.py` (empty) and `app/routers/client.py`**

```python
import time

from fastapi import APIRouter

from ..envelope import ok_env

router = APIRouter(prefix="/api/v1")


@router.get("/meta/health")
def health():
    return ok_env({"status": "alive"})


@router.get("/meta/time")
def server_time():
    return ok_env({"ts": int(time.time())})
```

- [ ] **Step 4: Implement `app/main.py`**

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .db import init_db
from .envelope import ApiError, envelope
from .routers import client


def create_app() -> FastAPI:
    app = FastAPI(title="KeyAuth License Server", openapi_url="/api/v1/openapi.json")

    @app.on_event("startup")
    def _startup():
        init_db()

    @app.exception_handler(ApiError)
    async def _api_error_handler(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(False, exc.code, None, exc.message),
        )

    app.include_router(client.router)
    return app


app = create_app()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_meta.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/main.py app/routers tests/test_meta.py
git commit -m "feat: app factory, ApiError handler, meta endpoints"
```

---

### Task 9: `auth/handshake` endpoint

**Files:**
- Modify: `app/routers/client.py` (add handshake route + helpers)
- Test: `tests/test_handshake.py`

**Interfaces:**
- Consumes: `HandshakeReq`, `app.services.license`, `app.security`, `app.db`, `app.ratelimit.limiter`.
- Produces: `POST /api/v1/auth/handshake` → `ok_env({"challenge_id","server_nonce","ttl"})`.
- Helper added to client.py: `_client_ip(request) -> str` (uses `request.client.host`).
- Validation order: rate-limit (by ip) → ts window → nonce unused → product exists+active → sig valid → key exists. On any failure raise `ApiError`. On success: store nonce, create challenge row, return challenge.

- [ ] **Step 1: Write failing test `tests/test_handshake.py`**

```python
import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap():
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        secret = p["app_secret"]
    return secret, raw


def _handshake_body(secret, raw, hwid="HW1", ts=None, nonce="n1"):
    ts = ts or int(time.time())
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return {"product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}


def test_handshake_success():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    r = client.post("/api/v1/auth/handshake", json=_handshake_body(secret, raw))
    body = r.json()
    assert body["ok"] is True
    assert body["data"]["challenge_id"]
    assert body["data"]["server_nonce"]


def test_handshake_bad_signature():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    bad = _handshake_body(secret, raw)
    bad["sig"] = "deadbeef"
    r = client.post("/api/v1/auth/handshake", json=bad)
    assert r.status_code == 401
    assert r.json()["code"] == "auth_failed"


def test_handshake_stale_timestamp():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    old = int(time.time()) - 9999
    r = client.post("/api/v1/auth/handshake", json=_handshake_body(secret, raw, ts=old))
    assert r.json()["code"] == "invalid_request"


def test_handshake_replayed_nonce():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    body = _handshake_body(secret, raw)
    assert client.post("/api/v1/auth/handshake", json=body).json()["ok"] is True
    r2 = client.post("/api/v1/auth/handshake", json=body)
    assert r2.json()["code"] == "invalid_request"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_handshake.py -q`
Expected: FAIL (404/Not Found — route missing).

- [ ] **Step 3: Add handshake to `app/routers/client.py`**

Add these imports at the top of the file (merge with existing):

```python
from fastapi import APIRouter, Request

from .. import db, security
from ..envelope import ApiError, ok_env
from ..models import HandshakeReq
from ..ratelimit import limiter
from ..services import license as lic
```

Add helpers + route:

```python
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
```

Note: keep the existing `import time` at the top (already present from Task 8).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_handshake.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add app/routers/client.py tests/test_handshake.py
git commit -m "feat: auth/handshake with sig, ts-window, nonce-replay, rate-limit"
```

---

### Task 10: `auth/verify` endpoint (session issue + activation + single-session)

**Files:**
- Modify: `app/routers/client.py`
- Test: `tests/test_verify.py`

**Interfaces:**
- Consumes: `VerifyReq`, challenge row, `lic.activate_if_new`, `lic.is_expired`, `security.verify_sig`, session table.
- Produces: `POST /api/v1/auth/verify` → `ok_env({"token","expires_at","product","key_expires_at"})`.
- Behavior: validate ts; load challenge by id (exists/unexpired/unused) → mark used; verify `answer_sig = HMAC(app_secret, challenge_id|server_nonce|key|hwid|ts)`; load key; reject if `banned`; if `unused` → activate (binds hwid); if `active` → enforce HWID match (mismatch ⇒ `hwid_mismatch` + clone audit); reject if expired; **revoke all prior sessions for this key (single active session)**; insert new session (token hashed); audit `login`.

- [ ] **Step 1: Write failing test `tests/test_verify.py`**

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
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], duration)
        secret = p["app_secret"]
    return secret, raw


def _full_auth(client, secret, raw, hwid="HW1"):
    ts = int(time.time())
    nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    hs = client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid,
        "nonce": nonce, "ts": ts, "sig": sig}).json()
    cid = hs["data"]["challenge_id"]
    snonce = hs["data"]["server_nonce"]
    ts2 = int(time.time())
    answer = security.sign(secret, cid, snonce, raw, hwid, ts2)
    return client.post("/api/v1/auth/verify", json={
        "challenge_id": cid, "key": raw, "hwid": hwid,
        "ts": ts2, "answer_sig": answer})


def test_verify_success_issues_token():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    r = _full_auth(client, secret, raw)
    body = r.json()
    assert body["ok"] is True
    assert body["data"]["token"]


def test_verify_hwid_mismatch_after_activation():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    assert _full_auth(client, secret, raw, hwid="HW1").json()["ok"] is True
    r = _full_auth(client, secret, raw, hwid="HW2")
    assert r.status_code == 403
    assert r.json()["code"] == "hwid_mismatch"
    with db.db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM audit_logs WHERE event_type='clone_attempt'").fetchone()["c"]
    assert n == 1


def test_verify_expired_key():
    secret, raw = _bootstrap(duration=1)
    client = TestClient(create_app())
    assert _full_auth(client, secret, raw).json()["ok"] is True
    time.sleep(2)
    r = _full_auth(client, secret, raw)
    assert r.json()["code"] == "expired"


def test_single_active_session():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    t1 = _full_auth(client, secret, raw).json()["data"]["token"]
    t2 = _full_auth(client, secret, raw).json()["data"]["token"]
    assert t1 != t2
    with db.db() as conn:
        active = conn.execute("SELECT COUNT(*) c FROM sessions WHERE revoked=0").fetchone()["c"]
    assert active == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verify.py -q`
Expected: FAIL (404 — route missing).

- [ ] **Step 3: Add to `app/routers/client.py`**

Add import: `from ..models import VerifyReq` (merge with existing model imports).

Add route:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_verify.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add app/routers/client.py tests/test_verify.py
git commit -m "feat: auth/verify with activation, hwid lock, expiry, single-session"
```

---

### Task 11: Session auth dependency + `license` status + `auth/heartbeat`

**Files:**
- Modify: `app/routers/client.py`
- Test: `tests/test_session_endpoints.py`

**Interfaces:**
- Produces:
  - Helper `_authed_session(conn, request) -> sqlite3.Row` — reads `Authorization: Bearer <token>`, looks up `sessions` by `hash_token`, validates not revoked + not expired, else `ApiError(401,"auth_failed")`.
  - `GET /api/v1/license` → `ok_env({"product","status","expires_at","hwid","hwid_reset_count"})`.
  - `POST /api/v1/auth/heartbeat` → re-checks key expiry/ban + session validity → `ok_env({"valid":True,"key_expires_at":...})`; expired/banned ⇒ corresponding `ApiError`.

- [ ] **Step 1: Write failing test `tests/test_session_endpoints.py`**

```python
import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap():
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], 3600)
        secret = p["app_secret"]
    return secret, raw


def _token(client, secret, raw, hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    hs = client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}).json()
    cid, snonce = hs["data"]["challenge_id"], hs["data"]["server_nonce"]
    ts2 = int(time.time()); answer = security.sign(secret, cid, snonce, raw, hwid, ts2)
    return client.post("/api/v1/auth/verify", json={
        "challenge_id": cid, "key": raw, "hwid": hwid, "ts": ts2, "answer_sig": answer}).json()["data"]["token"]


def test_license_status_requires_token():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    assert client.get("/api/v1/license").status_code == 401
    tok = _token(client, secret, raw)
    r = client.get("/api/v1/license", headers={"Authorization": f"Bearer {tok}"})
    assert r.json()["data"]["status"] == "active"


def test_heartbeat_ok():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    r = client.post("/api/v1/auth/heartbeat", headers={"Authorization": f"Bearer {tok}"})
    assert r.json()["data"]["valid"] is True


def test_revoked_session_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    tok = _token(client, secret, raw)
    with db.db() as conn:
        conn.execute("UPDATE sessions SET revoked=1")
    r = client.get("/api/v1/license", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_session_endpoints.py -q`
Expected: FAIL (401 for the status route happens, but the success path 404s — route missing).

- [ ] **Step 3: Add to `app/routers/client.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_session_endpoints.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add app/routers/client.py tests/test_session_endpoints.py
git commit -m "feat: session auth dependency, license status, heartbeat, logout"
```

---

### Task 12: `license/hwid/reset` with cooldown

**Files:**
- Modify: `app/routers/client.py`
- Test: `tests/test_hwid_reset.py`

**Interfaces:**
- Consumes: `HwidResetReq`, signing (same canonical fields as handshake), per-product cooldown override or global `hwid_reset_cooldown_days`.
- Produces: `POST /api/v1/license/hwid/reset` → on success `ok_env({"reset":True,"reset_count":N})`; if within cooldown ⇒ `ApiError(429,"cooldown", "...")` with remaining seconds in message.
- Behavior: rate-limit, ts, product+sig (like handshake), load key; compute cooldown = product override or global setting (days→seconds); if `last_hwid_reset_at` and `now - last < cooldown` ⇒ cooldown error; else unbind hwid (set NULL), increment `hwid_reset_count`, set `last_hwid_reset_at`, keep status (so timer continues), audit `hwid_reset`. On next verify the key re-binds the new HWID.

- [ ] **Step 1: Write failing test `tests/test_hwid_reset.py`**

```python
import time
from fastapi.testclient import TestClient
from app import db, security
from app.main import create_app
from app.services import license as lic
from app.ratelimit import limiter


def _bootstrap(cooldown_days=None):
    limiter.reset()
    with db.db() as conn:
        p = lic.create_product(conn, "manager", "Manager", "MASTERP", cooldown_days=cooldown_days)
        raw = lic.create_key(conn, p["id"], 3600)
        secret = p["app_secret"]
        # pre-activate + bind HW1
        row = lic.get_key_by_raw(conn, raw)
        lic.activate_if_new(conn, row, "HW1", int(time.time()))
    return secret, raw


def _reset_body(secret, raw, hwid="HW1"):
    ts = int(time.time()); nonce = security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return {"product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig}


def test_reset_success_then_cooldown():
    secret, raw = _bootstrap(cooldown_days=7)
    client = TestClient(create_app())
    r = client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw))
    assert r.json()["data"]["reset"] is True
    with db.db() as conn:
        k = lic.get_key_by_raw(conn, raw)
        assert k["hwid"] is None and k["hwid_reset_count"] == 1
    r2 = client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw))
    assert r2.status_code == 429
    assert r2.json()["code"] == "cooldown"


def test_reset_allowed_when_cooldown_zero():
    secret, raw = _bootstrap(cooldown_days=0)
    client = TestClient(create_app())
    assert client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw)).json()["data"]["reset"]
    assert client.post("/api/v1/license/hwid/reset", json=_reset_body(secret, raw)).json()["data"]["reset"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hwid_reset.py -q`
Expected: FAIL (404 — route missing).

- [ ] **Step 3: Add to `app/routers/client.py`**

Add import: `from ..models import HwidResetReq` (merge with existing model imports). Add route:

```python
@router.post("/license/hwid/reset")
def hwid_reset(req: HwidResetReq, request: Request):
    ip = _client_ip(request)
    with db.db() as conn:
        _rate_limit(conn, f"rs:{ip}")
        _check_ts(conn, req.ts)
        prod = lic.get_product(conn, req.product)
        if prod is None or not prod["active"]:
            raise ApiError(401, "auth_failed", "unknown product")
        if not security.verify_sig(prod["app_secret"], req.sig,
                                   req.product, req.key, req.hwid, req.nonce, req.ts):
            raise ApiError(401, "auth_failed", "bad signature")
        _consume_nonce(conn, req.nonce)
        k = lic.get_key_by_raw(conn, req.key)
        if k is None:
            raise ApiError(401, "auth_failed", "invalid key")

        now = int(time.time())
        if prod["hwid_reset_cooldown_days"] is not None:
            cooldown_days = prod["hwid_reset_cooldown_days"]
        else:
            cooldown_days = db.get_setting(conn, "hwid_reset_cooldown_days")
        cooldown = cooldown_days * 86400
        last = k["last_hwid_reset_at"]
        if last is not None and now - last < cooldown:
            remaining = cooldown - (now - last)
            raise ApiError(429, "cooldown", f"{remaining} seconds remaining")

        conn.execute(
            "UPDATE license_keys SET hwid=NULL, hwid_reset_count=hwid_reset_count+1, "
            "last_hwid_reset_at=? WHERE id=?", (now, k["id"]))
        # if the key was active and bound, keep it active so the next verify re-binds
        if k["status"] == "active":
            conn.execute("UPDATE license_keys SET status='active' WHERE id=?", (k["id"],))
        new_count = k["hwid_reset_count"] + 1
        lic.audit(conn, "hwid_reset", key_id=k["id"], hwid=req.hwid, ip=ip)
        # revoke live sessions so the old machine drops
        conn.execute("UPDATE sessions SET revoked=1 WHERE key_id=? AND revoked=0", (k["id"],))
    return ok_env({"reset": True, "reset_count": new_count})
```

**Note on re-binding after reset:** once `hwid` is NULL, a later `auth/verify` finds `status != 'unused'` and `hwid != req.hwid` would normally raise `hwid_mismatch`. So Task 10's verify must treat a NULL `hwid` as bindable. **Add this guard to the verify route's HWID branch** (modify the `elif` in Task 10):

```python
        elif key_row["hwid"] is None:
            conn.execute("UPDATE license_keys SET hwid=?, hwid_set_at=? WHERE id=?",
                         (req.hwid, now, key_row["id"]))
            key_row = lic.get_key_by_raw(conn, req.key)
        elif key_row["hwid"] != req.hwid:
            ...  # existing clone_attempt branch
```

- [ ] **Step 4: Apply the verify re-bind guard**

Edit `app/routers/client.py` `verify()` so the HWID handling reads:

```python
        if key_row["status"] == "unused":
            lic.activate_if_new(conn, key_row, req.hwid, now)
            key_row = lic.get_key_by_raw(conn, req.key)
        elif key_row["hwid"] is None:
            conn.execute("UPDATE license_keys SET hwid=?, hwid_set_at=? WHERE id=?",
                         (req.hwid, now, key_row["id"]))
            key_row = lic.get_key_by_raw(conn, req.key)
        elif key_row["hwid"] != req.hwid:
            lic.audit(conn, "clone_attempt", key_id=key_row["id"], hwid=req.hwid, ip=ip, severity="high",
                      detail={"bound": key_row["hwid"], "attempted": req.hwid})
            raise ApiError(403, "hwid_mismatch", "key bound to another machine")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_hwid_reset.py tests/test_verify.py -q`
Expected: PASS (all).

- [ ] **Step 6: Commit**

```bash
git add app/routers/client.py tests/test_hwid_reset.py
git commit -m "feat: hwid self-reset with cooldown + verify re-bind after reset"
```

---

### Task 13: CLI (admin seed + product/key creation) + `.env.example`

**Files:**
- Create: `app/cli.py`
- Create: `.env.example`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `app.db`, `app.services.license`, `app.security`, `app.config.settings`.
- Produces (argparse subcommands):
  - `python -m app.cli seed-admin` — create admin from env if none exists.
  - `python -m app.cli create-product --slug --name --prefix [--cooldown-days N]` — prints the product `app_secret`.
  - `python -m app.cli create-key --product SLUG --days N [--count C] [--note ...]` — prints raw key(s).
  - Programmatic functions for testing: `seed_admin() -> bool`, `cmd_create_product(...) -> dict`, `cmd_create_key(...) -> list[str]`.

- [ ] **Step 1: Write failing test `tests/test_cli.py`**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -q`
Expected: FAIL (`ModuleNotFoundError: app.cli`).

- [ ] **Step 3: Implement `app/cli.py`**

```python
import argparse

from . import db, security
from .config import settings
from .services import license as lic


def seed_admin() -> bool:
    db.init_db()
    with db.db() as conn:
        exists = conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone()
        if exists:
            return False
        import time
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

    args = parser.parse_args(argv)
    if args.cmd == "seed-admin":
        print("created" if seed_admin() else "admin already exists")
    elif args.cmd == "create-product":
        prod = cmd_create_product(args.slug, args.name, args.prefix, args.cooldown_days)
        print(f"product '{prod['slug']}' created. app_secret={prod['app_secret']}")
    elif args.cmd == "create-key":
        for raw in cmd_create_key(args.product, args.days, args.count, args.note):
            print(raw)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Create `.env.example`**

```
DB_PATH=keyauth.db
SERVER_SECRET=replace-with-64-random-hex-chars
ADMIN_USERNAME=admin
ADMIN_PASSWORD=replace-with-a-strong-password
DISCORD_WEBHOOK_URL=
ENVIRONMENT=dev
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -q`
Expected: PASS (2 tests).

- [ ] **Step 6: Wire admin seed into startup**

In `app/main.py` `_startup()`, after `init_db()`, add:

```python
        from .cli import seed_admin
        seed_admin()
```

- [ ] **Step 7: Commit**

```bash
git add app/cli.py app/main.py .env.example tests/test_cli.py
git commit -m "feat: CLI for admin seed + product/key creation, .env.example, startup seed"
```

---

### Task 14: Malicious-client simulation (the "server is not fooled" proof)

**Files:**
- Test: `tests/test_malicious_client.py`

**Interfaces:**
- Consumes: the full running app + helpers (reuse the auth helpers locally).
- Produces: a single test module that asserts the server rejects every cheat. No app code should change; if a test fails, fix the corresponding endpoint.

- [ ] **Step 1: Write the adversarial test `tests/test_malicious_client.py`**

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
        p = lic.create_product(conn, "manager", "Manager", "MASTERP")
        raw = lic.create_key(conn, p["id"], duration)
        secret = p["app_secret"]
    return secret, raw


def _handshake(client, secret, raw, hwid="HW1", nonce=None, ts=None):
    ts = ts or int(time.time()); nonce = nonce or security.new_nonce()
    sig = security.sign(secret, "manager", raw, hwid, nonce, ts)
    return client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": hwid, "nonce": nonce, "ts": ts, "sig": sig})


def test_forged_signature_without_secret_is_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    ts = int(time.time())
    sig = security.sign("attacker-guessed-secret", "manager", raw, "HW1", "n", ts)
    r = client.post("/api/v1/auth/handshake", json={
        "product": "manager", "key": raw, "hwid": "HW1", "nonce": "n", "ts": ts, "sig": sig})
    assert r.status_code == 401 and r.json()["code"] == "auth_failed"


def test_replayed_handshake_is_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    ts = int(time.time()); nonce = "fixed-nonce"
    sig = security.sign(secret, "manager", raw, "HW1", nonce, ts)
    body = {"product": "manager", "key": raw, "hwid": "HW1", "nonce": nonce, "ts": ts, "sig": sig}
    assert client.post("/api/v1/auth/handshake", json=body).json()["ok"] is True
    assert client.post("/api/v1/auth/handshake", json=body).json()["code"] == "invalid_request"


def test_replayed_challenge_answer_is_rejected():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    hs = _handshake(client, secret, raw).json()["data"]
    ts2 = int(time.time())
    answer = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, "HW1", ts2)
    body = {"challenge_id": hs["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts2, "answer_sig": answer}
    assert client.post("/api/v1/auth/verify", json=body).json()["ok"] is True
    # reusing the same challenge again must fail (single-use)
    assert client.post("/api/v1/auth/verify", json=body).status_code == 401


def test_cloned_hwid_cannot_run_in_parallel():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    # legit machine HW1 authenticates
    hs = _handshake(client, secret, raw, hwid="HW1").json()["data"]
    ts = int(time.time())
    ans = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, "HW1", ts)
    tok1 = client.post("/api/v1/auth/verify", json={
        "challenge_id": hs["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts, "answer_sig": ans}
    ).json()["data"]["token"]
    # attacker spoofs the SAME hwid (HW1) and authenticates -> supersedes session
    hs2 = _handshake(client, secret, raw, hwid="HW1").json()["data"]
    ts2 = int(time.time())
    ans2 = security.sign(secret, hs2["challenge_id"], hs2["server_nonce"], raw, "HW1", ts2)
    client.post("/api/v1/auth/verify", json={
        "challenge_id": hs2["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts2, "answer_sig": ans2})
    # original token is now revoked -> parallel use impossible
    r = client.get("/api/v1/license", headers={"Authorization": f"Bearer {tok1}"})
    assert r.status_code == 401


def test_different_hwid_is_rejected_and_logged():
    secret, raw = _bootstrap()
    client = TestClient(create_app())
    # activate on HW1
    hs = _handshake(client, secret, raw, hwid="HW1").json()["data"]
    ts = int(time.time())
    ans = security.sign(secret, hs["challenge_id"], hs["server_nonce"], raw, "HW1", ts)
    client.post("/api/v1/auth/verify", json={
        "challenge_id": hs["challenge_id"], "key": raw, "hwid": "HW1", "ts": ts, "answer_sig": ans})
    # HW2 tries
    hs2 = _handshake(client, secret, raw, hwid="HW2").json()["data"]
    ts2 = int(time.time())
    ans2 = security.sign(secret, hs2["challenge_id"], hs2["server_nonce"], raw, "HW2", ts2)
    r = client.post("/api/v1/auth/verify", json={
        "challenge_id": hs2["challenge_id"], "key": raw, "hwid": "HW2", "ts": ts2, "answer_sig": ans2})
    assert r.status_code == 403 and r.json()["code"] == "hwid_mismatch"
```

- [ ] **Step 2: Run the full suite**

Run: `pytest -q`
Expected: ALL PASS. If any adversarial test fails, fix the relevant endpoint (do not weaken the test).

- [ ] **Step 3: Commit**

```bash
git add tests/test_malicious_client.py
git commit -m "test: adversarial client simulation (forgery, replay, clone, hwid)"
```

---

## Phase 1 Done — Definition of Done

- `pytest -q` is fully green (unit + integration + adversarial).
- A product + key can be created via CLI, and a simulated client can complete `handshake → verify → license/heartbeat`, with HWID locking, expiry, single-session, cooldown reset, replay/forgery rejection all enforced server-side.
- No threshold is hardcoded; all are in `settings` and overridable.
- Run locally: `uvicorn app.main:app --reload` then hit `GET /api/v1/meta/health`.

## Deferred to later phases (tracked, not forgotten)

- **Phase 2:** server-side anti-clone *detection* (concurrent-use, impossible-travel, IP-velocity, fan-out heuristics) + encrypted gated **payload** delivery (`GET /api/v1/files/{product}/{resource}`) + Discord-less alert hooks.
- **Phase 3:** admin **web dashboard** (Jinja2) + admin REST API (`/admin/api/v1/...`) + **Discord webhook** notifications + Dockerfile/deploy + HTTPS guidance.
