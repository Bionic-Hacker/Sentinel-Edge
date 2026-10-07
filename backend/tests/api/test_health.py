from fastapi.testclient import TestClient


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}


def test_health_does_not_fingerprint_deployment(client: TestClient) -> None:
    body = client.get("/api/v1/health").text.lower()
    for leak in ("environment", "postgres", "python", "hostname", "test"):
        assert leak not in body


def test_capabilities_require_authentication(client: TestClient) -> None:
    """Phase 1 interim exposure T-API-06, closed in Phase 2."""
    response = client.get("/api/v1/platform/capabilities")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
