# keyauth — Hardened License-Key Server

A KeyAuth-style **license-key server** built with **FastAPI + SQLite**. It issues, validates, and manages subscription license keys with strict one-machine (HWID) binding (anti-clone) and records all activity.

**Guiding principle:** the server treats every client as hostile. All trust, validation, and (in later phases) the actual product payload live **server-side**. A tampered or cracked client cannot fool the server.

> **Status:** Phase 1 (server foundation + core validation) complete — 40 tests passing. Phases 2–3 are on the roadmap below. ⚠️ The encrypted **gated-payload** endpoint that is the *core anti-crack leverage* lands in **Phase 2** — Phase 1 alone does not yet deliver gated-payload anti-crack.

## Security model

| Attack | Defense |
|---|---|
| Replay | per-request nonce + timestamp window + single-use server challenge |
| Forged / tampered request | HMAC-SHA256 over canonical fields, per-product secret, constant-time compare |
| HWID spoof / clone | key binds to first HWID; mismatch rejected + logged; **one active session per key** so a cloned HWID can't run in parallel |
| Key brute-force | ~100-bit keys, sliding-window rate-limit, coarse error codes (no oracle) |
| Token theft | tokens stored hashed, short TTL, instantly revocable |
| Admin attack | argon2 password hashing |

All operational thresholds (TTLs, cooldowns, windows, limits) live in a runtime-tunable `settings` table — **nothing is hardcoded**.

## Setup

This project uses an **isolated virtualenv** (do not install its pinned deps into your global Python).

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # *nix
```

Copy `.env.example` to `.env` and set `SERVER_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `DISCORD_WEBHOOK_URL` (Phase 3), etc.

## Run

```bash
.venv/Scripts/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# Production: run behind nginx/Caddy with TLS terminated (HTTPS is required).
```

## CLI (create products & keys)

```bash
.venv/Scripts/python -m app.cli seed-admin
.venv/Scripts/python -m app.cli create-product --slug manager --name "Masterp Manager" --prefix MASTERP
.venv/Scripts/python -m app.cli create-key --product manager --days 30 --count 10
```

## Client API (signed; HTTPS + JSON + HMAC-SHA256)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/meta/health` | liveness |
| `GET` | `/api/v1/meta/time` | server time (avoid clock-skew lockouts) |
| `POST` | `/api/v1/auth/handshake` | start auth → single-use challenge |
| `POST` | `/api/v1/auth/verify` | answer challenge → session token |
| `POST` | `/api/v1/auth/heartbeat` | keepalive + live ban/expiry re-check |
| `DELETE` | `/api/v1/auth/session` | logout / release seat |
| `GET` | `/api/v1/license` | authenticated key status |
| `POST` | `/api/v1/license/hwid/reset` | self-reset HWID (cooldown enforced) |

Every response uses a uniform envelope: `{ "ok": bool, "code": str, "data": object|null, "message": str }`. Auto-generated OpenAPI at `/api/v1/openapi.json`. Client SDKs (Python / Go / Node) are intentionally thin and come in a later phase.

## Testing

```bash
.venv/Scripts/python -m pytest -q
```

Includes `tests/test_malicious_client.py` — an adversarial suite proving the server rejects forged signatures, replays, reused challenges, cloned-HWID parallel use, and HWID mismatch.

## Roadmap

- **Phase 1 (done):** auth flow, HWID lock, single-session, subscription keys, settings, rate-limit, CLI, adversarial tests.
- **Phase 2:** server-side anti-clone *detection* (concurrent-use / impossible-travel / IP-velocity), token IP-binding, `X-Forwarded-For`, and the **gated `/files/{product}/{resource}` payload** (the real anti-crack leverage).
- **Phase 3:** admin web dashboard + admin REST API + Discord webhook alerts + Dockerfile/deploy.

Design spec: [`docs/superpowers/specs/2026-06-29-license-key-server-design.md`](docs/superpowers/specs/2026-06-29-license-key-server-design.md)
Phase 1 plan: [`docs/superpowers/plans/2026-06-29-license-server-phase1-foundation.md`](docs/superpowers/plans/2026-06-29-license-server-phase1-foundation.md)

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
