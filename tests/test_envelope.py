from app.envelope import envelope, ok_env, ApiError


def test_envelope_shape():
    e = envelope(False, "auth_failed", message="nope")
    assert e == {"ok": False, "code": "auth_failed", "data": None, "message": "nope"}
    assert ok_env({"x": 1}) == {"ok": True, "code": "ok", "data": {"x": 1}, "message": ""}


def test_api_error_carries_fields():
    err = ApiError(401, "auth_failed", "bad")
    assert err.status_code == 401 and err.code == "auth_failed" and err.message == "bad"
