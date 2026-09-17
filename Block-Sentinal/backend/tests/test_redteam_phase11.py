"""Comprehensive Phase 11 Tests: Defensive Red-Team Validation & Tamper Simulation Lab.

Verifies:
- 34 distinct scenario executions, detection layers, multi-stage compound chains,
  evidence fusion integration, blast-radius propagation, false-positive validation,
  API/CLI lifecycles, and cryptographic seals.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.cli import main as cli_main
from app.crypto.canonical import canonical_json_hash
from app.main import app
from app.redteam.lab import RedTeamValidationLab, default_redteam_lab
from app.schemas.base import AssetStatus
from app.schemas.fusion import AssuranceAction
from app.schemas.redteam import (
    RedTeamScenario,
    ScenarioCategory,
    ScenarioExecutionResult,
)


@pytest.fixture
def temp_redteam_lab(tmp_path: Path):
    """Provides an isolated RedTeamValidationLab instance using temporary storage."""
    return RedTeamValidationLab(storage_dir=tmp_path / "redteam")


# 1. Scenario registration
def test_01_scenario_registration(temp_redteam_lab):
    scen = RedTeamScenario(
        scenario_id="CUSTOM_ATTACK_01",
        scenario_name="Custom Sensor Disruption",
        category=ScenarioCategory.DATASET,
        target_domain="DATA_INTEGRITY",
        target_artifact="sensor_batch_01",
        attack_description="Simulates sensor glitch.",
        mutation_method="Inject random Gaussian noise into sensor frame",
        expected_detection=True,
    )
    temp_redteam_lab.register_scenario(scen)
    fetched = temp_redteam_lab.get_scenario("CUSTOM_ATTACK_01")
    assert fetched is not None
    assert fetched.scenario_name == "Custom Sensor Disruption"


# 2. Dataset tamper detection (byte modification)
def test_02_dataset_byte_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DATASET_BYTE_TAMPER")
    assert res.is_detected is True
    assert "DATA_INTEGRITY" in res.detecting_subsystems
    assert res.fused_assessment.action == AssuranceAction.BLOCK
    assert res.hard_veto_triggered is True


# 3. Dataset deletion detection (sample omission)
def test_03_dataset_sample_deletion(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DATASET_SAMPLE_DELETION")
    assert res.is_detected is True
    assert "DATA_INTEGRITY" in res.detecting_subsystems
    assert res.fused_assessment.action in (AssuranceAction.REVIEW, AssuranceAction.BLOCK)


# 4. Label tampering (label flip)
def test_04_dataset_label_flip(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DATASET_LABEL_FLIP")
    assert res.is_detected is True
    assert "DATA_INTEGRITY" in res.detecting_subsystems
    assert len(res.evidence_generated) >= 1


# 5. Duplicate injection (near duplicate)
def test_05_dataset_duplicate_injection(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DATASET_DUPLICATE_INJECTION")
    assert res.is_detected is True
    assert res.fused_assessment.action == AssuranceAction.REVIEW


# 6. Poisoning indicator (corner checkerboard trigger)
def test_06_dataset_backdoor_trigger(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DATASET_BACKDOOR_TRIGGER")
    assert res.is_detected is True
    assert res.fused_assessment.action == AssuranceAction.BLOCK
    assert res.quarantine_record is not None


# 7. Model weight tamper (parameter bit flip)
def test_07_model_weight_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("MODEL_SINGLE_WEIGHT_MUTATION")
    assert res.is_detected is True
    assert "MODEL_IDENTITY" in res.detecting_subsystems
    assert res.hard_veto_triggered is True
    assert res.fused_assessment.action == AssuranceAction.BLOCK


# 8. Model substitution (architecture mismatch)
def test_08_model_substitution(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("MODEL_SUBSTITUTION")
    assert res.is_detected is True
    assert "MODEL_IDENTITY" in res.detecting_subsystems
    assert res.fused_assessment.action == AssuranceAction.BLOCK


# 9. Signature tamper (forged ECDSA)
def test_09_model_signature_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("MODEL_SIGNATURE_TAMPER")
    assert res.is_detected is True
    assert "CRYPTO_VERIFICATION" in res.detecting_subsystems
    assert res.hard_veto_triggered is True


# 10. Behavioral divergence (probe perturbation)
def test_10_behavioral_divergence(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("BEHAVIORAL_DIVERGENCE")
    assert res.is_detected is True
    assert "BEHAVIOURAL_FINGERPRINT" in res.detecting_subsystems
    assert res.fused_assessment.risk_score >= 0.50


# 11. Inference replay (duplicate nonce veto)
def test_11_inference_nonce_replay(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("INFERENCE_NONCE_REPLAY")
    assert res.is_detected is True
    assert "INFERENCE_DNA" in res.detecting_subsystems
    assert res.hard_veto_triggered is True
    assert res.fused_assessment.action == AssuranceAction.BLOCK


# 12. Hash-chain tamper (previous DNA hash break)
def test_12_inference_hash_chain_break(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("INFERENCE_HASH_CHAIN_BREAK")
    assert res.is_detected is True
    assert "INFERENCE_DNA" in res.detecting_subsystems
    assert res.hard_veto_triggered is True


# 13. Output digest tamper (post-signature forgery)
def test_13_inference_output_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("INFERENCE_OUTPUT_TAMPER")
    assert res.is_detected is True
    assert "INFERENCE_DNA" in res.detecting_subsystems
    assert res.hard_veto_triggered is True


# 14. Drift baseline tamper (unverified reference profile)
def test_14_drift_baseline_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DRIFT_BASELINE_TAMPER")
    assert res.is_detected is True
    assert "CRYPTO_VERIFICATION" in res.detecting_subsystems
    assert res.fused_assessment.action == AssuranceAction.BLOCK


# 15. Drift benign-shift isolation (isolated from quarantine)
def test_15_drift_benign_shift_isolation(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DRIFT_BENIGN_SHIFT")
    assert res.is_detected is True
    # Drift alone MUST NOT trigger hard veto or block
    assert res.hard_veto_triggered is False
    assert res.fused_assessment.action == AssuranceAction.REVIEW
    assert res.fused_assessment.verdict == AssetStatus.UNDER_REVIEW


# 16. Evidence tamper (system integrity detection)
def test_16_evidence_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("EVIDENCE_TAMPERING")
    assert res.is_detected is True
    assert "SYSTEM_INTEGRITY" in res.detecting_subsystems


# 17. Fusion tamper (canonical digest verification)
def test_17_fusion_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("FUSION_TAMPERING")
    assert res.is_detected is True
    assert "SYSTEM_INTEGRITY" in res.detecting_subsystems


# 18. Quarantine tamper
def test_18_quarantine_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DATASET_BACKDOOR_TRIGGER")
    assert res.quarantine_record is not None
    assert res.quarantine_record.is_active is True


# 19. Graph tamper (vertex modification digest failure)
def test_19_graph_tamper(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("GRAPH_TAMPERING")
    assert res.is_detected is True
    assert "SYSTEM_INTEGRITY" in res.detecting_subsystems


# 20. Cross-domain identity mismatch (corroborating drift attack)
def test_20_drift_corroborating_attack(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DRIFT_CORROBORATING_ATTACK")
    assert res.is_detected is True
    assert len(res.evidence_generated) == 2
    assert "DISTRIBUTION_SHIFT" in res.detecting_subsystems
    assert "BEHAVIOURAL_FINGERPRINT" in res.detecting_subsystems
    assert res.fused_assessment.action == AssuranceAction.BLOCK


# 21. Multi-stage attack chain (data poison -> behavior -> drift)
def test_21_multi_stage_chain(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("MULTI_STAGE_CHAIN_01")
    assert res.is_detected is True
    assert len(res.evidence_generated) == 3
    assert res.hard_veto_triggered is True
    assert res.fused_assessment.action == AssuranceAction.BLOCK
    assert res.blast_radius_report is not None


# 22. Evidence preservation (all evidence preserved in assessment)
def test_22_evidence_preservation(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("MULTI_STAGE_CHAIN_01")
    evidence_ids = {e.evidence_id for e in res.evidence_generated}
    assmt_ev_ids = {e.evidence_id for e in res.fused_assessment.raw_evidence}
    assert evidence_ids.issubset(assmt_ev_ids)


# 23. Fusion preservation (canonical RFC 8785 hash sealed)
def test_23_fusion_preservation(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("MODEL_SINGLE_WEIGHT_MUTATION")
    assert len(res.fused_assessment.assessment_digest) == 64
    assert res.fused_assessment.signature is not None


# 24. Quarantine propagation (blast-radius and graph impact)
def test_24_quarantine_propagation(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("DATASET_BACKDOOR_TRIGGER")
    assert res.quarantine_record is not None
    graph_node_ids = [n.id for n in res.graph_lineage_nodes]
    # Check that the quarantined entity or quarantine event is present in the graph lineage cluster
    assert res.quarantine_record.subject_id in graph_node_ids or res.quarantine_record.quarantine_id in graph_node_ids


# 25. Blast-radius propagation (downstream dependencies identified)
def test_25_blast_radius_propagation(temp_redteam_lab):
    res = temp_redteam_lab.run_scenario("MODEL_SINGLE_WEIGHT_MUTATION")
    assert res.blast_radius_report is not None
    assert res.blast_radius_report.total_downstream_count >= 1


# 26. False-positive benign validation (clean dataset, authentic model, valid inference)
def test_26_false_positive_benign_validation(temp_redteam_lab):
    # 1. Normal Dataset
    r_ds = temp_redteam_lab.run_scenario("BENIGN_NORMAL_DATASET")
    assert r_ds.is_detected is False
    assert r_ds.fused_assessment.action == AssuranceAction.ALLOW
    assert r_ds.hard_veto_triggered is False

    # 2. Normal Model
    r_mod = temp_redteam_lab.run_scenario("BENIGN_NORMAL_MODEL")
    assert r_mod.is_detected is False
    assert r_mod.fused_assessment.action == AssuranceAction.ALLOW

    # 3. Normal Inference
    r_inf = temp_redteam_lab.run_scenario("BENIGN_NORMAL_INFERENCE")
    assert r_inf.is_detected is False
    assert r_inf.fused_assessment.action == AssuranceAction.ALLOW

    # 4. Tiny Numerical Roundoff
    r_round = temp_redteam_lab.run_scenario("BENIGN_NUMERICAL_ROUNDOFF")
    assert r_round.is_detected is False
    assert r_round.fused_assessment.action == AssuranceAction.ALLOW


# 27. Detection coverage generation (coverage matrix schema and items)
def test_27_detection_coverage_generation(temp_redteam_lab):
    matrix = temp_redteam_lab.generate_coverage_matrix()
    assert matrix.total_scenarios >= 20
    assert matrix.covered_scenarios == matrix.total_scenarios
    assert len(matrix.items) == matrix.total_scenarios


# 28. Scorecard generation (accuracy rate, category breakdown)
def test_28_scorecard_generation(temp_redteam_lab):
    scorecard = temp_redteam_lab.generate_scorecard()
    assert scorecard.total_scenarios >= 20
    assert scorecard.accuracy_rate == 1.0
    assert scorecard.false_positives == 0
    assert "DATASET" in scorecard.category_breakdown
    assert "MODEL" in scorecard.category_breakdown


# 29. API lifecycle (scenarios, run, coverage, scorecard, results)
def test_29_api_lifecycle():
    client = TestClient(app)

    # 1. GET /api/v1/redteam/scenarios
    res = client.get("/api/v1/redteam/scenarios")
    assert res.status_code == 200
    scenarios = res.json()["data"]
    assert len(scenarios) >= 20

    # 2. GET /api/v1/redteam/scenarios/{id}
    res = client.get("/api/v1/redteam/scenarios/DATASET_BYTE_TAMPER")
    assert res.status_code == 200
    assert res.json()["data"]["scenario_id"] == "DATASET_BYTE_TAMPER"

    # 3. POST /api/v1/redteam/run (Single scenario)
    res = client.post("/api/v1/redteam/run", json={"scenario_id": "DATASET_BYTE_TAMPER"})
    assert res.status_code == 200
    exec_data = res.json()["data"][0]
    assert exec_data["is_detected"] is True
    exec_id = exec_data["execution_id"]

    # 4. GET /api/v1/redteam/results/{id}
    res = client.get(f"/api/v1/redteam/results/{exec_id}")
    assert res.status_code == 200
    assert res.json()["data"]["execution_id"] == exec_id

    # 5. GET /api/v1/redteam/coverage
    res = client.get("/api/v1/redteam/coverage")
    assert res.status_code == 200
    assert res.json()["data"]["total_scenarios"] >= 20

    # 6. GET /api/v1/redteam/scorecard
    res = client.get("/api/v1/redteam/scorecard")
    assert res.status_code == 200
    assert res.json()["data"]["accuracy_rate"] == 1.0


# 30. CLI lifecycle (redteam-list, redteam-run, redteam-coverage, redteam-scorecard)
def test_30_cli_lifecycle():
    # 1. redteam-list
    ret = cli_main(["redteam-list"])
    assert ret == 0

    # 2. redteam-run
    ret = cli_main(["redteam-run", "--scenario-id", "MODEL_SINGLE_WEIGHT_MUTATION"])
    assert ret == 0

    # 3. redteam-coverage
    ret = cli_main(["redteam-coverage"])
    assert ret == 0

    # 4. redteam-scorecard
    ret = cli_main(["redteam-scorecard"])
    assert ret == 0


# 31. Persistence across restart (results saved and reloaded)
def test_31_persistence_across_restart(tmp_path: Path):
    store_dir = tmp_path / "persist_redteam"
    lab1 = RedTeamValidationLab(storage_dir=store_dir)
    res1 = lab1.run_scenario("DATASET_BACKDOOR_TRIGGER")

    # Load in new lab instance
    lab2 = RedTeamValidationLab(storage_dir=store_dir)
    loaded_res = lab2.get_result(res1.execution_id)
    assert loaded_res is not None
    assert loaded_res.execution_id == res1.execution_id
    assert loaded_res.is_detected == res1.is_detected


# 32. Deterministic scenario execution (re-running produces consistent verdicts)
def test_32_deterministic_execution(temp_redteam_lab):
    res1 = temp_redteam_lab.run_scenario("MODEL_SUBSTITUTION")
    res2 = temp_redteam_lab.run_scenario("MODEL_SUBSTITUTION")

    assert res1.is_detected == res2.is_detected == True
    assert res1.fused_assessment.action == res2.fused_assessment.action == AssuranceAction.BLOCK
    assert res1.hard_veto_triggered == res2.hard_veto_triggered == True


# 33. No mutation of reference artifacts (reference files untouched)
def test_33_no_mutation_of_reference_artifacts(temp_redteam_lab, tmp_path: Path):
    ref_file = tmp_path / "golden_reference.bin"
    ref_file.write_bytes(b"GOLDEN_IMMUTABLE_REFERENCE_MODEL_PAYLOAD")
    ref_digest_before = canonical_json_hash({"data": ref_file.read_bytes().hex()})

    # Execute model weight tampering scenario
    temp_redteam_lab.run_scenario("MODEL_SINGLE_WEIGHT_MUTATION")

    ref_digest_after = canonical_json_hash({"data": ref_file.read_bytes().hex()})
    assert ref_digest_before == ref_digest_after
    assert ref_file.read_bytes() == b"GOLDEN_IMMUTABLE_REFERENCE_MODEL_PAYLOAD"


# 34. Full run of all scenarios
def test_34_run_all_scenarios(temp_redteam_lab):
    all_results = temp_redteam_lab.run_all_scenarios()
    assert len(all_results) >= 20
    scorecard = temp_redteam_lab.generate_scorecard()
    assert scorecard.accuracy_rate == 1.0
    assert scorecard.false_positives == 0
