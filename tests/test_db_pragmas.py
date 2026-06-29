from app import db


def test_connection_pragmas_applied():
    with db.db() as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 1
        assert conn.execute("PRAGMA synchronous").fetchone()[0] in (1, 2)  # NORMAL=1


def test_journal_mode_is_wal():
    with db.db() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
