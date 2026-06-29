# License Key Server — Design Spec

- **Date:** 2026-06-29
- **Status:** Approved (brainstorming complete)
- **Scope of this spec:** The **server only**. Client SDKs are explicitly out of scope for v1.
- **Stack:** Python + FastAPI, SQLite, Jinja2 (admin UI), Argon2 (admin password), HMAC-SHA256 (request signing).

## 1. Goal & guiding principle

Build a hardened license-key server that issues, validates, and manages subscription license keys with strict one-machine (HWID) binding (anti-clone), and records all activity for the operator.

**Guiding principle (the requirement that overrides convenience):** the server treats every client as hostile and **must not be fooled by a tampered or cracked client**. All trust, validation, and the actual product payload live server-side. The client is never trusted to enforce anything.

## 2. Decisions locked during brainstorming

| Decision | Choice |
|---|---|
| What to build first | **Server only.** Client SDKs (Lua loader, desktop) come later. |
| Backend stack | Python + FastAPI |
| Database | SQLite (file-based; designed so Postgres migration is possible later) |
| Expiry model | **Subscription only** — every key has a duration |
| HWID policy | **1 machine per key**, user self-reset with cooldown; clone attempts rejected + logged |
| Products/tiers | **Multiple products** — keys are scoped to a product |
| Admin auth | **Single admin login** (seeded from env) |
| Logging / visibility | **Web dashboard + Discord webhook** alerts |
| Trust/anti-tamper model | **B — Challenge-response + server-gated payload** (HMAC signing as a layer) |

## 3. Threat model & defenses

This is the core of the system. Each row is a property the implementation and tests must guarantee.

| Attack | Defense |
|---|---|
| **Replay** of a captured valid request | Per-request **nonce + timestamp window (±30s)**; server issues a **single-use challenge** that must be answered; used client nonces cached and rejected within the window |
| **Forge / tamper** with request fields | **HMAC-SHA256** over the canonical request, keyed by the per-product app secret; signature mismatch → reject |
| **Spoof / rotate HWID** to bypass the lock | Key binds to first HWID seen at activation; any mismatch is **rejected + logged as a clone attempt + Discord alert**; HWID changes rate-limited; heuristics flag "many HWIDs on one key" and "one HWID across many keys" |
| **Brute-force / enumerate keys** | ~100-bit random keys; **rate-limit + lockout** per IP and per key+HWID; constant-time comparison; coarse error reasons to avoid an oracle |
| **Bypass the license check entirely** (cracked client) | The product payload is **encrypted and delivered ONLY through an authenticated session**. A client that skips auth never receives the product. This is the real anti-crack leverage. |
| **Steal / hijack a session token** | Tokens are random 256-bit, **stored hashed server-side**, short TTL, bound to HWID+IP, and **instantly revocable** by admin |
| **Attack the admin login** | **Argon2** password hashing, login rate-limit, session cookie `HttpOnly`/`Secure`/`SameSite=Strict`, CSRF protection |
| **Network MITM** | **TLS/HTTPS is mandatory** (terminated at a reverse proxy). HMAC authenticates but does not encrypt. |

### Documented honest limitations
- Any app-secret embedded in a *future* client can eventually be extracted by a determined reverse-engineer. This is universal to such systems. Extraction only allows request forgery — it does **not** yield a valid key or the payload. The gated-payload design makes extraction worthless.
- HWID is ultimately client-asserted. The server cannot cryptographically prove the hardware, so the defense is binding + rejection + rate-limiting + detection + logging, not prevention of assertion. This is stated plainly so expectations are correct.
- Full DoS protection (volumetric) is out of scope; basic rate-limiting is in scope.

## 4. Data model (SQLite)

- **products** — `id`, `slug` (unique), `name`, `app_secret`, `hwid_reset_cooldown_days` (nullable override of global), `active`, `created_at`
- **license_keys** — `id`, `key_hash` (sha256 of raw key — raw key never stored), `key_prefix` (display/search), `product_id` (FK), `duration_seconds`, `status` (`unused`/`active`/`expired`/`banned`), `hwid`, `hwid_set_at`, `hwid_reset_count`, `last_hwid_reset_at`, `activated_at`, `expires_at`, `note`, `created_at`
- **admins** — `id`, `username` (unique), `password_hash` (argon2), `last_login_at`, `created_at`
- **sessions** — `id`, `token_hash`, `key_id` (FK), `hwid`, `ip`, `issued_at`, `expires_at`, `revoked`
- **challenges** — `id`, `server_nonce`, `key_id` (FK, nullable until matched), `hwid`, `ip`, `expires_at`, `used`
- **used_nonces** — `nonce`, `seen_at` (rows pruned once past the timestamp window)
- **audit_logs** — `id`, `ts`, `event_type`, `key_id` (nullable), `hwid`, `ip`, `severity`, `detail_json`
- **payloads** — `id`, `product_id` (FK), `resource_slug`, `ciphertext`, `nonce`, `created_at`

Indexes: unique on `license_keys.key_hash`, `products.slug`, `admins.username`, `sessions.token_hash`; lookup indexes on `audit_logs(ts)`, `challenges(expires_at)`, `used_nonces(seen_at)`.

## 5. Key lifecycle & subscription model

- **Format:** `PROD-XXXXX-XXXXX-XXXXX-XXXXX` — Crockford base32, ~100 bits of entropy, generated with the `secrets` module.
- **Storage:** only `sha256(raw_key)` + a short prefix are stored. The raw key is shown once at creation.
- **Activation-based timer:** the subscription clock starts at **first successful auth**, not at creation, so unsold keys do not burn time. On first auth: bind HWID, set `activated_at = now`, `expires_at = now + duration_seconds`, status → `active`.
- **State machine:** `unused → active → expired`. Admin may set `banned` from any state. Expiry is evaluated on every auth and heartbeat.

## 6. Client protocol (Model B — challenge-response + gated payload)

All client requests are signed: `sig = HMAC_SHA256(product.app_secret, canonical_request)`.

1. **`POST /api/v1/handshake`** — body `{product, key, hwid, nonce, ts, sig}`. Server verifies sig, timestamp window, and nonce-unused; looks up the key; returns `{challenge_id, server_nonce, ttl}`. A short-lived single-use `challenges` row is created.
2. **`POST /api/v1/auth`** — body `{challenge_id, key, hwid, ts, answer_sig}` where `answer_sig = HMAC(app_secret, challenge_id|server_nonce|key|hwid|ts)`. Server validates: challenge exists/unexpired/unused; signature; key active/unexpired/product-match/not-banned; HWID bound-or-bindable. On success: bind/confirm HWID, activate if first use, issue a **session token**, mark challenge used, write `login` audit log, fire Discord notification.
3. **`GET /api/v1/payload/{product}/{resource}`** — requires a valid session token. Server decrypts the `payloads` row and returns the protected content. **This is the only path to the product.**
4. **`POST /api/v1/hwid/reset`** — signed. If `now - last_hwid_reset_at >= cooldown`, unbind HWID, increment `hwid_reset_count`, set `last_hwid_reset_at`, log + Discord alert. Otherwise reject with remaining cooldown time.
5. **`GET /api/v1/heartbeat`** — requires session; revalidates expiry/ban/revocation so a revoked or expired session stops working live.

Error responses use coarse, stable codes (`invalid_request`, `auth_failed`, `expired`, `hwid_mismatch`, `rate_limited`, `banned`) — enough for client UX without becoming an enumeration oracle.

## 7. HWID / anti-clone logic

- First successful auth binds the HWID.
- A later auth with a different HWID → reject (`hwid_mismatch`) + `clone_attempt` audit log (severity high) + Discord alert.
- Self-reset allowed once per cooldown (global default, e.g. 7 days, with optional per-product override).
- Admin can force-reset HWID or ban a key at any time.
- Detection heuristics produce flagged alerts: many distinct HWIDs attempted against one key; one HWID used across many keys.

## 8. Admin dashboard

- Server-rendered (Jinja2). Single admin account **seeded from env on first boot**; password changeable from the UI.
- Pages: **Products** (create/list/toggle), **Keys** (create single, **bulk-generate**, search by prefix/status, revoke, force-reset HWID, ban), **Logs** (filter by event type/severity/key), **Sessions** (view/revoke active sessions).
- JSON admin API under `/admin/api/...` for automation (e.g. bulk key generation by scripts).
- Session-cookie auth with CSRF; login rate-limited.

## 9. Discord notifications

- Webhook URL from env. Events: new activation, **clone attempt (high severity)**, HWID reset, ban, admin login, server start.
- Sent asynchronously and failure-tolerant (a webhook outage never blocks or breaks auth). Light batching/rate-limiting to avoid spam floods.

## 10. Config & secrets

`.env` (with a committed `.env.example`, real `.env` git-ignored):
`SERVER_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` (hashed into the DB on first boot, then the env value can be removed), `DISCORD_WEBHOOK_URL`, `DB_PATH`, session/challenge TTLs, HWID cooldown days, rate-limit thresholds, `ENVIRONMENT` (`dev`/`prod`). Per-product `app_secret` values are generated and stored in the DB when a product is created.

## 11. Module layout

```
keyauth/
├── app/
│   ├── main.py            # FastAPI app, router wiring, middleware (rate limit, security headers)
│   ├── config.py          # settings loaded from env
│   ├── db.py              # SQLite connection + schema/migrations + pruning jobs
│   ├── models.py          # Pydantic request/response schemas
│   ├── security.py        # HMAC sign/verify, nonce store, key generation, argon2, tokens, constant-time compare
│   ├── notify.py          # Discord webhook (async, failure-tolerant)
│   ├── payload.py         # encrypted payload storage + gated delivery
│   ├── services/
│   │   ├── license.py     # validate/activate/expiry/clone-detection
│   │   └── admin.py       # admin operations
│   └── routers/
│       ├── client.py      # public signed client endpoints
│       └── admin.py       # admin endpoints + dashboard
├── templates/             # Jinja2 admin templates
├── tests/                 # pytest (unit + integration + malicious-client simulation)
├── .env.example
├── requirements.txt
└── Dockerfile
```

## 12. Testing strategy (TDD)

pytest, written test-first per the project's TDD discipline. Coverage must include:
- **Security units:** HMAC verify, key-generation entropy/format, argon2 round-trip, constant-time compare, nonce store.
- **Protocol/integration:** full handshake → auth → payload happy path; **replay rejected**; **forged signature rejected**; **expired key rejected**; **clone attempt rejected + logged**; cooldown enforced; rate-limit/lockout triggers; session revocation takes effect live.
- **Malicious-client simulation:** a test harness that replays, tampers, and rotates HWID to prove the server is not fooled. This is a required, named test module.
- **Admin:** login success/failure, rate-limit, key CRUD, bulk generation, force-reset, ban.

## 13. Error handling

Coarse, stable error codes (section 6); never leak stack traces or secrets in `prod`; full detail written to `audit_logs` internally. Webhook/Discord failures are swallowed and logged, never fatal to auth.

## 14. Deployment

Run with uvicorn behind nginx/Caddy with **TLS terminated at the proxy (HTTPS required)**. Dockerfile + run instructions provided. Admin seeded from env on first boot. SQLite file path configurable; document backup (copy the file) and the Postgres-migration path.

## 15. Out of scope for v1 (future work)

- **Client SDKs** (Lua executor loader, Windows desktop integration) — explicitly later, per the "server first" decision.
- Reseller accounts / credit limits, multiple admin users, 2FA, Postgres migration, payment-provider integration.
