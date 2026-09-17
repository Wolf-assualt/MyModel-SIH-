import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/system/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"] is not None
    assert payload["data"]["status"] == "healthy"
    assert payload["data"]["app"] == "TRUST-CV"
    assert payload["data"]["version"] == "1.0.0"


def test_status_endpoint():
    response = client.get("/api/v1/system/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"] is not None
    assert payload["data"]["database"] == "connected"
    assert payload["data"]["status"] == "operational"
