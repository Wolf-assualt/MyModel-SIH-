"""Tests for database tables, foreign keys, and relational lineage."""
import pytest
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError

from app.models.contributor import Contributor
from app.models.dataset import Dataset, DatasetBatch
from app.models.sample import Sample
from app.models.model import Model, ModelFingerprint
from app.models.inference import InferenceRecord
from app.models.assessment import AssuranceAssessment
from app.models.finding import Finding
from app.models.evidence import Evidence
from app.models.audit import AuditEvent, MerkleRoot
from app.models.attack import AttackScenario


def test_full_evidence_relational_lineage(db_session):
    """Verify complete evidence lineage traversal:
    Contributor -> Dataset -> Batch -> Sample -> Model -> Inference -> Finding -> Evidence -> Audit Event
    """
    # 1. Contributor
    contributor = Contributor(
        name="Field Sensor Unit Alpha",
        organization="Northern Command",
        trust_score=0.98,
        total_samples=100,
        suspicious_samples=2,
        risk_level="Low Risk",
    )
    db_session.add(contributor)
    db_session.commit()
    assert contributor.id is not None

    # 2. Dataset
    dataset = Dataset(
        name="Border Patrol Surveillance DS-1",
        format="COCO",
        root_path="/data/clean/ds1",
        sha256_digest="a" * 64,
        total_samples=50,
        contributor_id=contributor.id,
    )
    db_session.add(dataset)
    db_session.commit()

    # 3. Dataset Batch
    batch = DatasetBatch(
        dataset_id=dataset.id,
        batch_number=1,
        sha256_digest="b" * 64,
        sample_count=50,
        status="INGESTED",
    )
    db_session.add(batch)
    db_session.commit()

    # 4. Sample
    sample = Sample(
        batch_id=batch.id,
        contributor_id=contributor.id,
        file_path="/data/clean/ds1/frame_001.jpg",
        sha256_digest="c" * 64,
        perceptual_hash="1010101010101010",
        label="vehicle",
        split="train",
    )
    db_session.add(sample)
    db_session.commit()

    # 5. Model
    model = Model(
        name="Tactical Object Detector v2",
        framework="ONNX",
        format=".onnx",
        version="2.1.0",
        file_path="/models/tactical_v2.onnx",
        sha256_digest="d" * 64,
        parameters_count=25000000,
        size_bytes=104857600,
    )
    db_session.add(model)
    db_session.commit()

    # 6. Model Fingerprint
    fingerprint = ModelFingerprint(
        model_id=model.id,
        weights_sha256="e" * 64,
        benchmark_digest="f" * 64,
    )
    db_session.add(fingerprint)
    db_session.commit()

    # 7. Inference Record (Inference DNA)
    inference = InferenceRecord(
        model_id=model.id,
        sample_id=sample.id,
        input_sha256="c" * 64,
        model_sha256="d" * 64,
        preprocessing_sha256="1" * 64,
        config_sha256="2" * 64,
        output_sha256="3" * 64,
        prediction_json='{"class": "vehicle", "confidence": 0.94}',
        confidence=0.94,
        nonce="n" * 32,
        sequence_number=1,
        prev_record_hash="0" * 64,
        record_hash="4" * 64,
    )
    db_session.add(inference)
    db_session.commit()

    # 8. Assurance Assessment
    assessment = AssuranceAssessment(
        target_type="INFERENCE",
        target_id=inference.id,
        overall_assurance_score=92.5,
        risk_level="LOW",
        confidence=0.95,
        evidence_coverage=1.0,
        recommended_disposition="ACCEPT",
    )
    db_session.add(assessment)
    db_session.commit()

    # 9. Finding
    finding = Finding(
        assessment_id=assessment.id,
        sample_id=sample.id,
        inference_id=inference.id,
        finding_type="EXACT_DUPLICATE",
        severity="INFO",
        confidence=1.0,
        affected_asset_type="SAMPLE",
        affected_asset_id=sample.id,
        evidence_summary="Cryptographic SHA-256 match confirmed across batch.",
        limitation="Cannot assess visual similarity beyond byte-level equivalence.",
        recommended_action="Keep single canonical copy in dataset.",
    )
    db_session.add(finding)
    db_session.commit()

    # 10. Evidence
    evidence = Evidence(
        finding_id=finding.id,
        evidence_type="HASH_PROOF",
        metric_name="digest_match_count",
        metric_value=1.0,
        sha256_proof="c" * 64,
    )
    db_session.add(evidence)
    db_session.commit()

    # 11. Audit Event (Hash Chain)
    audit = AuditEvent(
        sequence_number=1,
        event_type="INFERENCE_VERIFIED",
        entity_type="INFERENCE",
        entity_id=inference.id,
        actor="ASSURANCE_ENGINE",
        payload_sha256="5" * 64,
        prev_event_hash="0" * 64,
        event_hash="6" * 64,
    )
    db_session.add(audit)
    db_session.commit()

    # 12. Merkle Root
    merkle = MerkleRoot(
        batch_id=batch.id,
        root_hash="7" * 64,
        leaf_count=50,
        block_height=1,
    )
    db_session.add(merkle)
    db_session.commit()

    # 13. Attack Scenario
    attack = AttackScenario(
        scenario_name="Adversarial Patch Trigger Injection Test",
        attack_class="TRIGGER_INJECTION",
        is_simulation=True,
        parameters_json='{"patch_size": 32, "location": "bottom_right"}',
        target_asset_type="MODEL",
        target_asset_id=model.id,
        detection_status="DETECTED",
        detection_confidence=0.98,
        evidence_summary="Trigger indicator triggered on localized perturbation test.",
    )
    db_session.add(attack)
    db_session.commit()

    # Verify relationships and traversals
    # Contributor -> Dataset -> Batch -> Sample
    queried_contributor = db_session.get(Contributor, contributor.id)
    assert len(queried_contributor.datasets) == 1
    assert queried_contributor.datasets[0].name == "Border Patrol Surveillance DS-1"
    assert len(queried_contributor.datasets[0].batches) == 1
    assert queried_contributor.datasets[0].batches[0].sample_count == 50
    assert len(queried_contributor.datasets[0].batches[0].samples) == 1
    assert queried_contributor.datasets[0].batches[0].samples[0].label == "vehicle"

    # Sample -> Inference -> Finding -> Evidence
    queried_sample = db_session.get(Sample, sample.id)
    assert len(queried_sample.inferences) == 1
    assert queried_sample.inferences[0].record_hash == "4" * 64
    assert len(queried_sample.findings) == 1
    assert queried_sample.findings[0].finding_type == "EXACT_DUPLICATE"
    assert len(queried_sample.findings[0].evidence_items) == 1
    assert queried_sample.findings[0].evidence_items[0].sha256_proof == "c" * 64


def test_foreign_key_enforcement(db_session):
    """Verify that foreign keys prevent orphaned entities in SQLite."""
    # Attempt to insert a Dataset with non-existent contributor_id
    invalid_dataset = Dataset(
        name="Orphaned Dataset",
        format="COCO",
        root_path="/invalid/path",
        sha256_digest="x" * 64,
        total_samples=0,
        contributor_id="non-existent-contributor-id",
    )
    db_session.add(invalid_dataset)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_nonce_and_sequence_constraints(db_session):
    """Verify that duplicate nonces in InferenceRecords are rejected."""
    model = Model(
        name="Test Model",
        framework="PyTorch",
        format=".pt",
        version="1.0.0",
        file_path="/models/test.pt",
        sha256_digest="m" * 64,
        size_bytes=1000,
    )
    db_session.add(model)
    db_session.commit()

    inf1 = InferenceRecord(
        model_id=model.id,
        input_sha256="i" * 64,
        model_sha256="m" * 64,
        preprocessing_sha256="p" * 64,
        config_sha256="c" * 64,
        output_sha256="o" * 64,
        prediction_json='{"pred": 1}',
        nonce="duplicate-nonce-1234567890",
        sequence_number=1,
        prev_record_hash="0" * 64,
        record_hash="h1" + "0" * 62,
    )
    db_session.add(inf1)
    db_session.commit()

    # Attempt to insert identical nonce
    inf2 = InferenceRecord(
        model_id=model.id,
        input_sha256="i" * 64,
        model_sha256="m" * 64,
        preprocessing_sha256="p" * 64,
        config_sha256="c" * 64,
        output_sha256="o" * 64,
        prediction_json='{"pred": 2}',
        nonce="duplicate-nonce-1234567890",
        sequence_number=2,
        prev_record_hash="h1" + "0" * 62,
        record_hash="h2" + "0" * 62,
    )
    db_session.add(inf2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
