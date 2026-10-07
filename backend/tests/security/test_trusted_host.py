"""Host header allow-list — mitigates host-header injection and cache poisoning."""

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.security


@pytest.mark.parametrize("host", ["evil.example", "testserver.evil.example", "127.0.0.2"])
def test_unexpected_host_rejected(client: TestClient, host: str) -> None:
    response = client.get("/api/v1/health", headers={"Host": host})
    assert response.status_code == 400


def test_expected_host_allowed(client: TestClient) -> None:
    assert client.get("/api/v1/health").status_code == 200
