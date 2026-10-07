"""When the database is unreachable, readiness fails closed and says nothing useful to attackers."""

from collections.abc import Callable

from fastapi.testclient import TestClient


def test_not_ready_when_database_unreachable(client_factory: Callable[..., TestClient]) -> None:
    client = client_factory(db_host="127.0.0.1", db_port=1, db_password="unused")
    response = client.get("/api/v1/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "not_ready"
    text = response.text.lower()
    for leak in ("127.0.0.1", "psycopg", "operationalerror", "connection refused", "port"):
        assert leak not in text
