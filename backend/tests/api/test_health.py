from fastapi.testclient import TestClient


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}


def test_health_does_not_fingerprint_deployment(client: TestClient) -> None:
    body = client.get("/api/v1/health").text.lower()
    for leak in ("environment", "postgres", "python", "hostname", "test"):
        assert leak not in body


def test_capabilities_endpoint_lists_register(client: TestClient) -> None:
    response = client.get("/api/v1/platform/capabilities")
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) > 0
    assert {"key", "provenance", "status", "phase"} <= items[0].keys()
