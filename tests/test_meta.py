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
