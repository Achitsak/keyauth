import contextlib
import sqlite3
import time

from .config import settings, SETTINGS_DEFAULTS
from .envelope import ApiError

_DB_PATH = settings.db_path


def set_db_path(path: str) -> None:
    global _DB_PATH
    _DB_PATH = path


@contextlib.contextmanager
def db():
    """Yield a SQLite connection. Commits on clean exit AND on ApiError (so single-use/audit/state writes made before a handled error persist); rolls back on any other exception. Always closes."""
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={settings.db_busy_timeout_ms}")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-8000")
    conn.execute("PRAGMA mmap_size=268435456")
    try:
        yield conn
        conn.commit()
    except ApiError:
        try:
            conn.commit()
        except Exception:
            pass
        raise
    except Exception:
        raise
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
        conn.execute("PRAGMA journal_mode=WAL")
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
