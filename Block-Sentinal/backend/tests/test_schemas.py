"""Tests for Pydantic schema validation, digest boundaries, and enums."""
import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.schemas.contributor import ContributorCreate, ContributorResponse
from app.schemas.dataset import DatasetCreate, SampleCreate
from app.schemas.model import ModelCreate
from app.schemas.inference import InferenceCreate, InferenceDNATuple
from app.schemas.finding import FindingCreate
from app.schemas.common import RiskLevel, Disposition, Severity, FindingType, ModelFramework, DatasetFormat


def test_contributor_schema_validation():
    """Verify contributor creation and validation."""
    data = {
        "name": "Radar Surveillance Lab",
        "organization": "DRDO",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA",
    }
    schema = ContributorCreate(**data)
    assert schema.name == "Radar Surveillance Lab"
    assert schema.organization == "DRDO"

    # Name too short
    with pytest.raises(ValidationError):
        ContributorCreate(name="A", organization="DRDO")


def test_sha256_digest_strict_length_enforcement():
    """Verify that hashes must strictly be 64 hexadecimal characters."""
    valid_hash = "a" * 64
    invalid_short_hash = "a" * 63
    invalid_long_hash = "a" * 65

    # Valid dataset
    ds = DatasetCreate(
        name="Valid DS",
        format=DatasetFormat.COCO,
        root_path="/path/to/ds",
        sha256_digest=valid_hash,
        contributor_id="contributor-123",
    )
    assert ds.sha256_digest == valid_hash

    # Invalid short hash
    with pytest.raises(ValidationError):
        DatasetCreate(
            name="Invalid DS",
            format=DatasetFormat.COCO,
            root_path="/path/to/ds",
            sha256_digest=invalid_short_hash,
            contributor_id="contributor-123",
        )

    # Invalid long hash
    with pytest.raises(ValidationError):
        DatasetCreate(
            name="Invalid DS",
            format=DatasetFormat.COCO,
            root_path="/path/to/ds",
            sha256_digest=invalid_long_hash,
            contributor_id="contributor-123",
        )


def test_inference_dna_tuple_schema():
    """Verify that InferenceDNATuple enforces all required provenance fields."""
    dna = InferenceDNATuple(
        input_sha256="1" * 64,
        model_sha256="2" * 64,
        preprocessing_sha256="3" * 64,
        config_sha256="4" * 64,
        output_sha256="5" * 64,
        nonce="n" * 32,
        timestamp=datetime.now(timezone.utc),
        sequence_number=42,
        prev_record_hash="0" * 64,
    )
    assert dna.sequence_number == 42
    assert dna.nonce == "n" * 32


def test_finding_enums_and_boundaries():
    """Verify FindingCreate validates enums and confidence boundaries."""
    finding = FindingCreate(
        finding_type=FindingType.POISONING_INDICATOR,
        severity=Severity.HIGH,
        confidence=0.88,
        affected_asset_type="DATASET",
        affected_asset_id="ds-uuid",
        evidence_summary="Anomalous label clustering detected.",
        limitation="Cluster density heuristic only.",
        recommended_action="Inspect batch partition.",
    )
    assert finding.finding_type == FindingType.POISONING_INDICATOR
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.88

    # Out of range confidence (> 1.0)
    with pytest.raises(ValidationError):
        FindingCreate(
            finding_type=FindingType.POISONING_INDICATOR,
            severity=Severity.HIGH,
            confidence=1.5,
            affected_asset_type="DATASET",
            affected_asset_id="ds-uuid",
            evidence_summary="Invalid confidence",
            limitation="None",
            recommended_action="None",
        )
