"""Unit and integration tests for Phase 13: Red-Team & Adversarial Attack Lab."""
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.crypto.chain import HashChain
from app.crypto.signer import KeyManager
from app.inference.dna import InferenceDNAGenerator
from app.inference.verifier import InferenceDNAVerifier
from app.integrity.engine import DataIntegrityEngine
from app.main import app
from app.models_engine.registry import ModelRegistry
from app.redteam.runner import RedTeamLab
from app.schemas.base import AssetStatus
from app.schemas.redteam import (
    AttackExecutionRequest,
    AttackExecutionResult,
    AttackType,
    AttackVerificationReport,
)


@pytest.fixture
def temp_redteam_lab(tmp_path: Path):
    """Provides an isolated RedTeamLab with sandboxed engines and temporary directories."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    km = KeyManager()
    chain = HashChain()
    dna_gen = InferenceDNAGenerator(key_manager=km, chain=chain, storage_dir=data_dir / "inference_dna")
    dna_ver = InferenceDNAVerifier()
    int_engine = DataIntegrityEngine(reports_dir=data_dir / "reports")
    mod_registry = ModelRegistry(base_dir=data_dir / "models")

    return RedTeamLab(
        data_dir=data_dir,
        integrity_engine=int_engine,
        model_registry=mod_registry,
        dna_generator=dna_gen,
        dna_verifier=dna_ver,
    )


def test_label_flipping_attack_and_detection(temp_redteam_lab):
    """Verify label flipping mutates sample labels and is detected by DataIntegrityEngine."""
    req = AttackExecutionRequest(
        attack_type=AttackType.LABEL_FLIPPING,
        target_entity_id="batch_label_test",
        intensity=0.5,
        target_label="adversarial_flipped",
    )

    result = temp_redteam_lab.execute_attack(req)
    assert isinstance(result, AttackExecutionResult)
    assert result.attack_type == AttackType.LABEL_FLIPPING
    assert result.samples_modified_count >= 1
    assert result.modified_entity_id == "batch_label_test_flipped"

    # Verify detection
    report = temp_redteam_lab.verify_detection(result)
    assert isinstance(report, AttackVerificationReport)
    assert report.attack_id == result.attack_id
    assert report.detected_by_engine is True
    assert report.detecting_subsystem == "DATA_INTEGRITY"
    assert report.assigned_verdict in (AssetStatus.UNDER_REVIEW, AssetStatus.QUARANTINED)


def test_backdoor_trigger_injection_and_detection(temp_redteam_lab):
    """Verify stamping checkerboard trigger pattern causes TRIGGER_BACKDOOR critical detection."""
    req = AttackExecutionRequest(
        attack_type=AttackType.BACKDOOR_TRIGGER,
        target_entity_id="batch_backdoor_test",
        intensity=0.5,
        target_label="target_class_vehicle",
    )

    result = temp_redteam_lab.execute_attack(req)
    assert isinstance(result, AttackExecutionResult)
    assert result.attack_type == AttackType.BACKDOOR_TRIGGER
    assert result.samples_modified_count >= 2
    assert result.modified_entity_id == "batch_backdoor_test_backdoored"

    # Verify detection
    report = temp_redteam_lab.verify_detection(result)
    assert isinstance(report, AttackVerificationReport)
    assert report.attack_id == result.attack_id
    assert report.detected_by_engine is True
    assert report.detecting_subsystem == "DATA_INTEGRITY"
    assert report.assigned_verdict == AssetStatus.QUARANTINED
    assert report.confidence >= 0.99
    assert "TRIGGER_BACKDOOR" in report.details.get("finding_types", [])


def test_sample_corruption_and_detection(temp_redteam_lab):
    """Verify zero-variance blackout array injection causes CORRUPT_OR_OOD detection."""
    req = AttackExecutionRequest(
        attack_type=AttackType.DATASET_CORRUPTION,
        target_entity_id="batch_corrupt_test",
        intensity=0.5,
    )

    result = temp_redteam_lab.execute_attack(req)
    assert isinstance(result, AttackExecutionResult)
    assert result.attack_type == AttackType.DATASET_CORRUPTION
    assert result.samples_modified_count >= 1

    # Verify detection
    report = temp_redteam_lab.verify_detection(result)
    assert isinstance(report, AttackVerificationReport)
    assert report.detected_by_engine is True
    assert report.detecting_subsystem == "DATA_INTEGRITY"
    assert "CORRUPT_OR_OOD" in report.details.get("finding_types", [])


def test_model_weight_tampering_and_detection(temp_redteam_lab):
    """Verify bit-flipping parameter bytes causes binary SHA-256 mismatch and quarantine."""
    req = AttackExecutionRequest(
        attack_type=AttackType.MODEL_WEIGHT_TAMPERING,
        target_entity_id="model_weights_test",
        intensity=0.5,
    )

    result = temp_redteam_lab.execute_attack(req)
    assert isinstance(result, AttackExecutionResult)
    assert result.attack_type == AttackType.MODEL_WEIGHT_TAMPERING

    # Verify detection
    report = temp_redteam_lab.verify_detection(result)
    assert isinstance(report, AttackVerificationReport)
    assert report.detected_by_engine is True
    assert report.detecting_subsystem == "MODEL_IDENTITY"
    assert report.assigned_verdict == AssetStatus.QUARANTINED
    assert report.confidence == 1.0
    assert report.details.get("binary_match") is False


def test_inference_output_tampering_and_detection(temp_redteam_lab):
    """Verify post-signature prediction tampering is caught by InferenceDNAVerifier."""
    req = AttackExecutionRequest(
        attack_type=AttackType.INFERENCE_TAMPERING,
        target_entity_id="dna_record_test",
        target_label="spoofed_detection",
    )

    result = temp_redteam_lab.execute_attack(req)
    assert isinstance(result, AttackExecutionResult)
    assert result.attack_type == AttackType.INFERENCE_TAMPERING

    # Verify detection
    report = temp_redteam_lab.verify_detection(result)
    assert isinstance(report, AttackVerificationReport)
    assert report.detected_by_engine is True
    assert report.detecting_subsystem == "INFERENCE_DNA"
    assert report.assigned_verdict == AssetStatus.QUARANTINED
    assert report.confidence == 1.0
    assert report.details.get("hash_integrity_valid") is False


def test_inference_replay_attack_and_detection(temp_redteam_lab):
    """Verify replaying an existing nonce triggers duplicate nonce rejection."""
    req = AttackExecutionRequest(
        attack_type=AttackType.INFERENCE_REPLAY,
        target_entity_id="dna_replay_test",
    )

    result = temp_redteam_lab.execute_attack(req)
    assert isinstance(result, AttackExecutionResult)
    assert result.attack_type == AttackType.INFERENCE_REPLAY

    # Verify detection
    report = temp_redteam_lab.verify_detection(result)
    assert isinstance(report, AttackVerificationReport)
    assert report.detected_by_engine is True
    assert report.detecting_subsystem == "INFERENCE_DNA"
    assert report.assigned_verdict == AssetStatus.QUARANTINED
    assert report.confidence == 1.0
    assert "Replay detected" in report.details.get("caught_exception", "")


def test_api_redteam_endpoints():
    """Test FastAPI /redteam/attack/execute and /redteam/attack/verify endpoints."""
    client = TestClient(app)

    # 1. Execute attack
    exec_payload = {
        "attack_type": "BACKDOOR_TRIGGER",
        "target_entity_id": "api_batch_recon_01",
        "intensity": 0.5,
        "target_label": "adversarial_tank",
    }
    res_exec = client.post("/api/v1/redteam/attack/execute", json=exec_payload)
    assert res_exec.status_code == 200
    body_exec = res_exec.json()
    assert body_exec["success"] is True
    exec_data = body_exec["data"]
    assert exec_data["attack_type"] == "BACKDOOR_TRIGGER"
    assert "attack_id" in exec_data

    # 2. Verify attack detection
    res_ver = client.post("/api/v1/redteam/attack/verify", json=exec_data)
    assert res_ver.status_code == 200
    body_ver = res_ver.json()
    assert body_ver["success"] is True
    ver_data = body_ver["data"]
    assert ver_data["detected_by_engine"] is True
    assert ver_data["detecting_subsystem"] == "DATA_INTEGRITY"
    assert ver_data["assigned_verdict"] == AssetStatus.QUARANTINED.value
