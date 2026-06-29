from app.config import settings, SETTINGS_DEFAULTS


def test_settings_have_defaults():
    assert settings.db_path
    assert SETTINGS_DEFAULTS["auth_ts_window_seconds"] == 30
    assert SETTINGS_DEFAULTS["session_ttl_seconds"] == 3600
    assert SETTINGS_DEFAULTS["hwid_reset_cooldown_days"] == 7
