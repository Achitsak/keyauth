from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    db_path: str = "keyauth.db"
    server_secret: str = "dev-server-secret-change-me"
    admin_username: str = "admin"
    admin_password: str = "change-me-on-first-boot"
    discord_webhook_url: str = ""
    environment: str = "dev"
    db_busy_timeout_ms: int = 5000


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
