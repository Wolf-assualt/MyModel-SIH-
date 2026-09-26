"""Phase 8 — Frontend ↔ Backend Integration Contract Tests.

Verifies the REAL API contracts consumed by the frontend clients (the served
vanilla-JS SOC dashboard and the React client). These tests guarantee that the
data the frontend renders is exactly what the backend produced:

  A. Upload + poll (real multipart upload, real background pipeline)
  B. ScanSession contract (status / stage / progress / stage_results / errors / warnings)
  C. PARTIAL semantics — UNAVAILABLE components must stay UNAVAILABLE
  D. Ledger contract — /ledger/verify, /ledger/events, /ledger/decision
  E. Analyst decision — persisted, signed, retrievable, validation enforced
  F. Evidence graph contract — /graph/export shape
  G. Readiness contract

No core engine is mocked. Fixtures are real files in memory. Air-gapped.
"""

from __future__ import annotations

import io
import time
import zipfile
from typing import Dict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.ledger.database import LedgerBase, get_ledger_db
from app.main import app

client = TestClient(app)

# ---------------------------------------------------------------------------
# Isolated in-memory ledger (mirrors backend/tests/test_ledger.py conventions).
#
# The on-disk ledger at DATA_DIR/ledger/ledger.db is persistent and shared, and
# analyst decisions are signed with a per-process ECDSA key, so chain-validity
# assertions are only deterministic against a fresh ledger within this process.
# ---------------------------------------------------------------------------

_contract_ledger_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
ContractLedgerSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_contract_ledger_engine)


@pytest.fixture(scope="function")
def isolated_ledger_client():
    """TestClient whose ledger dependency points at a fresh in-memory chain."""
    LedgerBase.metadata.create_all(bind=_contract_ledger_engine)
    session = ContractLedgerSessionLocal()

    def _override_get_ledger_db():
        try:
            yield session
        finally:
            pass

    app.dependency_overrides[get_ledger_db] = _override_get_ledger_db
    with TestClient(app) as isolated_client:
        yield isolated_client
    app.dependency_overrides.pop(get_ledger_db, None)
    session.close()
    LedgerBase.metadata.drop_all(bind=_contract_ledger_engine)

ALLOWED_SESSION_STATUSES = {"PENDING", "IN_PROGRESS", "COMPLETED", "FAILED"}
ALLOWED_COMPONENT_STATUSES = {"PENDING", "RUNNING", "PASSED", "FAILED", "UNAVAILABLE"}


def _poll_until_terminal(scan_id: str, max_seconds: float = 25.0) -> Dict:
    """Poll GET /scan/{id} until the backend reports a terminal status."""
    deadline = time.time() + max_seconds
    last: Dict = {}
    while time.time() < deadline:
        response = client.get(f"/api/v1/scan/{scan_id}")
        assert response.status_code == 200, response.text
        last = response.json()["data"]
        if last.get("status") in ("COMPLETED", "FAILED"):
            return last
        time.sleep(0.2)
    return last


def _make_zip(num_images: int = 2) -> bytes:
    """Build a real in-memory ZIP containing tiny valid PNG images."""
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover
        pytest.skip("Pillow not installed")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "a", zipfile.ZIP_DEFLATED, False) as zf:
        for i in range(num_images):
            img = Image.new("RGB", (8, 8), color=(i * 30 % 255, 100, 150))
            img_bytes = io.BytesIO()
            img.save(img_bytes, format="PNG")
            zf.writestr(f"img_{i}.png", img_bytes.getvalue())
    return buffer.getvalue()


def _upload(name: str, num_images: int = 2) -> Dict:
    response = client.post(
        "/api/v1/datasets/upload",
        data={"dataset_name": name},
        files={"files": (f"{name}.zip", _make_zip(num_images), "application/zip")},
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]


# ---------------------------------------------------------------------------
# A. Upload → ScanSession contract
# ---------------------------------------------------------------------------


class TestUploadContract:
    def test_upload_returns_real_scan_session_envelope(self):
        """POST /datasets/upload returns ResponseEnvelope[ScanSession] with real IDs."""
        data = _upload("phase8_contract")
        for field in ("scan_id", "status", "stage", "progress", "errors", "warnings"):
            assert field in data, f"ScanSession contract missing field: {field}"
        assert isinstance(data["scan_id"], str) and data["scan_id"]
        assert data["status"] in ALLOWED_SESSION_STATUSES

    def test_poll_unknown_scan_returns_404(self):
        """Unknown scan id must 404 so the UI shows UNAVAILABLE, not a fake state."""
        response = client.get("/api/v1/scan/definitely-not-a-real-scan-id")
        assert response.status_code == 404

    def test_error_envelope_shape_is_stable(self):
        """Backend errors use the shared ResponseEnvelope error contract."""
        response = client.get("/api/v1/scan/definitely-not-a-real-scan-id")
        body = response.json()
        assert body.get("success") is False
        assert isinstance(body.get("error"), str) and body["error"]


# ---------------------------------------------------------------------------
# B/C. ScanSession lifecycle + PARTIAL semantics
# ---------------------------------------------------------------------------


class TestScanLifecycleContract:
    def test_full_scan_preserves_backend_states(self):
        """Run a real scan; verify statuses are backend-produced and preserved."""
        scan_id = _upload("phase8_lifecycle")["scan_id"]
        session = _poll_until_terminal(scan_id)
        assert session["status"] in ("COMPLETED", "FAILED"), session["status"]

        assert isinstance(session.get("stage_results"), dict)
        assert isinstance(session.get("errors"), list)
        assert isinstance(session.get("warnings"), list)
        assert 0.0 <= session.get("progress", 0.0) <= 1.0

        for name, comp in session["stage_results"].items():
            assert comp["status"] in ALLOWED_COMPONENT_STATUSES, (
                f"{name}: illegal component status {comp['status']}"
            )
            if comp["status"] == "UNAVAILABLE":
                assert comp.get("explanation") or comp.get("error_code"), (
                    f"{name} UNAVAILABLE without explanation"
                )

    def test_completed_scan_assessment_contract(self):
        """Assessment carries the exact fields TrustScoreCard renders."""
        scan_id = _upload("phase8_assessment")["scan_id"]
        session = _poll_until_terminal(scan_id)
        assert session["status"] == "COMPLETED", session
        assessment = session.get("assessment")
        assert assessment is not None, "COMPLETED scan must expose an assessment"

        # assuranceScore is the value the frontend renders as the gauge.
        assert isinstance(assessment.get("assuranceScore"), (int, float))
        assert 0.0 <= assessment["assuranceScore"] <= 1.0
        # disposition drives the verdict badge — must be a backend value.
        assert isinstance(assessment.get("disposition"), str) and assessment["disposition"]
        # -1.0 is the backend's explicit "module UNAVAILABLE" sentinel.
        assert assessment.get("modelRiskScore") == -1.0
        assert assessment.get("inferenceRiskScore") == -1.0
        assert "totalSamples" in assessment and "flaggedSamples" in assessment

    def test_unavailable_modules_are_reported_not_assumed(self):
        """Without a model artifact, model/inference stages must be UNAVAILABLE."""
        scan_id = _upload("phase8_partial")["scan_id"]
        session = _poll_until_terminal(scan_id)
        stage_results = session["stage_results"]

        assert stage_results["MODEL_INTEGRITY"]["status"] == "UNAVAILABLE"
        assert stage_results["MODEL_INTEGRITY"]["error_code"] == "ERR_MODULE_OFFLINE"
        assert stage_results["INFERENCE_VALIDATION"]["status"] == "UNAVAILABLE"
        assert stage_results["BACKDOOR_ANALYSIS"]["status"] == "UNAVAILABLE"
        # OOD requires an external reference dataset.
        assert stage_results["OOD_DETECTION"]["status"] == "UNAVAILABLE"
        # The frontend must never receive a PASSED status for these.
        for name in ("MODEL_INTEGRITY", "INFERENCE_VALIDATION", "BACKDOOR_ANALYSIS", "OOD_DETECTION"):
            assert stage_results[name]["status"] != "PASSED"


# ---------------------------------------------------------------------------
# D/E. Ledger + analyst decision contract
# ---------------------------------------------------------------------------


class TestLedgerContract:
    def test_ledger_verify_shape(self):
        """GET /ledger/verify returns the exact keys the UI renders."""
        response = client.get("/api/v1/ledger/verify")
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        for key in ("valid", "events_checked", "last_verified_sequence", "first_invalid_sequence", "failure_reason"):
            assert key in data, f"Ledger verification contract missing: {key}"
        assert isinstance(data["valid"], bool)
        assert isinstance(data["events_checked"], int)

    def test_ledger_events_shape(self):
        """GET /ledger/events returns the fields the event table renders."""
        response = client.get("/api/v1/ledger/events?limit=5")
        assert response.status_code == 200, response.text
        events = response.json()["data"]
        assert isinstance(events, list)
        for event in events:
            for key in (
                "sequence", "timestamp", "event_type", "actor", "scan_id",
                "entity_id", "payload_hash", "previous_hash", "current_hash", "signature",
            ):
                assert key in event, f"Ledger event contract missing: {key}"

    def test_analyst_decision_is_persisted_signed_and_retrievable(self, isolated_ledger_client):
        """POST /ledger/decision seals a signed event readable from /ledger/events."""
        entity_id = "phase8_decision_entity"
        response = isolated_ledger_client.post(
            "/api/v1/ledger/decision",
            params={
                "entity_id": entity_id,
                "decision": "REVIEW",
                "actor": "phase8_test_analyst",
                "reason": "contract test",
            },
        )
        assert response.status_code == 200, response.text
        event = response.json()["data"]
        assert event["event_type"] == "analyst_decision"
        assert event["entity_id"] == entity_id
        assert event["actor"] == "phase8_test_analyst"
        # Analyst decisions are signed by the backend ECDSA key.
        assert event["signature"], "analyst decision must be cryptographically signed"

        # Read back through the entity endpoint the UI uses.
        readback = isolated_ledger_client.get(f"/api/v1/ledger/events/entity/{entity_id}")
        assert readback.status_code == 200, readback.text
        events = readback.json()["data"]
        assert any(
            e["event_type"] == "analyst_decision" and e["actor"] == "phase8_test_analyst"
            for e in events
        )

    def test_analyst_decision_rejects_invalid_value(self, isolated_ledger_client):
        """Only ACCEPT / REVIEW / QUARANTINE are legal decisions."""
        response = isolated_ledger_client.post(
            "/api/v1/ledger/decision",
            params={
                "entity_id": "phase8_bad_decision",
                "decision": "MAGICALLY_SAFE",
                "actor": "phase8_test_analyst",
            },
        )
        assert response.status_code == 400

    def test_ledger_still_valid_after_decisions(self, isolated_ledger_client):
        """Signed analyst decisions append without breaking the hash chain.

        Runs against an isolated in-memory ledger because the on-disk ledger is
        persistent, shared across suites, and signed decisions from a previous
        process cannot be verified by a later process (per-process ECDSA key) —
        making global-validity assertions non-deterministic in a shared DB.
        """
        before = isolated_ledger_client.get("/api/v1/ledger/verify").json()["data"]
        assert before["valid"] is True, before
        baseline = before["events_checked"]

        for decision in ("ACCEPT", "REVIEW"):
            resp = isolated_ledger_client.post(
                "/api/v1/ledger/decision",
                params={"entity_id": "phase8_chain_entity", "decision": decision, "actor": "phase8_chain_actor"},
            )
            assert resp.status_code == 200, resp.text

        after = isolated_ledger_client.get("/api/v1/ledger/verify").json()["data"]
        assert after["valid"] is True, after
        assert after["events_checked"] >= baseline + 2
        assert after["first_invalid_sequence"] is None


# ---------------------------------------------------------------------------
# F/G. Evidence graph + readiness contract
# ---------------------------------------------------------------------------


class TestGraphAndReadinessContract:
    def test_graph_export_shape(self):
        """GET /graph/export returns nodes/edges the EvidenceGraph renders."""
        response = client.get("/api/v1/graph/export")
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert "nodes" in data and "edges" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)
        for node in data["nodes"]:
            assert "id" in node and "node_type" in node
        for edge in data["edges"]:
            assert "source_id" in edge and "target_id" in edge

    def test_contributor_risk_endpoint_contract(self):
        """GET /graph/contributor/{id}/risk returns a real computed profile."""
        response = client.get("/api/v1/graph/contributor/phase8_contributor/risk")
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert "risk_score" in data
        assert 0.0 <= data["risk_score"] <= 1.0

    def test_readiness_contract(self):
        """GET /system/readiness exposes the fields the health badge renders."""
        response = client.get("/api/v1/system/readiness")
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["ready"] is True
        assert data["status"] == "healthy"
        assert data["crypto"] == "Ed25519"


# ---------------------------------------------------------------------------
# UI static assets served by the backend
# ---------------------------------------------------------------------------


class TestServedDashboardContract:
    def test_app_js_makes_no_local_crypto_verdict(self):
        """The served client must not fabricate a signature PASS/FAIL locally."""
        response = client.get("/static/js/app.js")
        assert response.status_code == 200
        source = response.text
        # Old fabricated handler: setTimeout → hardcoded "VALID" verdict.
        assert "SECP256R1 ECDSA MATCH" not in source, (
            "app.js still fabricates a signature verdict via setTimeout"
        )
        # Verification must be routed through the backend audit endpoint.
        assert "auditReportSignature" in source

    def test_app_js_preserves_unavailable_state(self):
        """UNAVAILABLE drift must no longer be rewritten to 'passed' client-side."""
        response = client.get("/static/js/app.js")
        assert response.status_code == 200
        source = response.text
        assert "s7 === 'UNAVAILABLE') s7 = 'passed'" not in source, (
            "app.js coerces UNAVAILABLE → passed for drift"
        )

    def test_api_client_exposes_ledger_and_decisions(self):
        """The served API client exposes the endpoints the panels consume."""
        response = client.get("/static/js/api.js")
        assert response.status_code == 200
        source = response.text
        for method in (
            "verifyLedger", "listLedgerEvents", "listLedgerEventsByScan",
            "listLedgerEventsByEntity", "recordAnalystDecision", "listAnalystDecisions",
        ):
            assert method in source, f"api.js missing client method: {method}"
