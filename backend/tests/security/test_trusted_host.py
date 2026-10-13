"""Host header allow-list — mitigates host-header injection and cache poisoning."""

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.security


@pytest.mark.parametrize("host", ["evil.example", "testserver.evil.example", "127.0.0.2"])
@pytest.mark.parametrize("path", ["/api/v1/ready", "/api/v1/auth/login", "/api/v1/nonexistent"])
def test_unexpected_host_rejected(client: TestClient, host: str, path: str) -> None:
    response = client.get(path, headers={"Host": host})
    assert response.status_code == 400


def test_expected_host_allowed(client: TestClient) -> None:
    assert client.get("/api/v1/health").status_code == 200


@pytest.mark.parametrize("host", ["10.40.10.180:8000", "127.0.0.1:8000"])
def test_liveness_probe_answers_a_load_balancer_by_ip(client: TestClient, host: str) -> None:
    # The ALB and the container health check address the task by IP and cannot send another Host.
    response = client.get("/api/v1/health", headers={"Host": host})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_only_get_on_the_exact_liveness_path_skips_the_check(client: TestClient) -> None:
    ip = {"Host": "10.40.10.180:8000"}
    assert client.post("/api/v1/health", headers=ip).status_code == 400
    assert client.get("/api/v1/health/", headers=ip).status_code == 400
    assert client.get("/api/v1/healthz", headers=ip).status_code == 400
    assert client.get("/api/v1/ready", headers=ip).status_code == 400
