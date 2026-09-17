"""Tests for UI Routes, Single-Page Operations Dashboard, and Static Assets."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_serve_command_center_root():
    """Test that GET / successfully serves the single-page dashboard HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    content = response.text
    assert "TRUST-CV" in content
    assert "Defense SOC" in content
    assert "Forensic Evidence & Provenance Graph" in content
    assert "canvas id=\"graph-canvas\"" in content
    assert "Adversarial Red-Team Lab" in content


def test_serve_static_stylesheet():
    """Test that GET /static/css/dashboard.css delivers the tactical defense stylesheet."""
    response = client.get("/static/css/dashboard.css")
    assert response.status_code == 200
    assert "text/css" in response.headers.get("content-type", "")
    content = response.text
    assert "tactical-grid" in content
    assert "obsidian" in content or "--bg-obsidian" in content
    assert "glow-cyan" in content


def test_serve_static_javascript_modules():
    """Test that all static JavaScript client modules are accessible and non-empty."""
    # 1. api.js
    res_api = client.get("/static/js/api.js")
    assert res_api.status_code == 200
    assert "javascript" in res_api.headers.get("content-type", "")
    assert "TrustCvApiClient" in res_api.text
    assert "window.TrustCvApi" in res_api.text

    # 2. graph.js
    res_graph = client.get("/static/js/graph.js")
    assert res_graph.status_code == 200
    assert "javascript" in res_graph.headers.get("content-type", "")
    assert "ProvenanceGraphRenderer" in res_graph.text
    assert "loadGraphData" in res_graph.text

    # 3. app.js
    res_app = client.get("/static/js/app.js")
    assert res_app.status_code == 200
    assert "javascript" in res_app.headers.get("content-type", "")
    assert "refreshAllData" in res_app.text
    assert "triggerAttack" in res_app.text


def test_static_nonexistent_returns_404():
    """Test that requesting a nonexistent static asset yields HTTP 404."""
    response = client.get("/static/js/non_existent_file_xyz.js")
    assert response.status_code == 404
