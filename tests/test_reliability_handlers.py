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
