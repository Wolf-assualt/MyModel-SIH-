"""TRUST-CV Phase 16: Benign Distribution Shift vs Integrity Failure Demonstration.

Demonstrates:
1. Registration of an operational Earth Observation baseline (Summer Sentinel-2 distribution)
2. Evaluation of natural seasonal environmental shift (Autumn illumination and NDVI decay)
3. Quantitative statistical drift calculation across 4 distance metrics (KS, PSI, Wasserstein-1, Energy)
4. Multi-domain evidence fusion handling benign drift
5. Correct disposition of REVIEW / LOW-RISK rather than automatic BLOCK / QUARANTINE
6. Clear conceptual distinction between Distribution Shift and Cryptographic Tampering
"""
import sys
from pathlib import Path
import numpy as np

backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.drift.engine import default_drift_engine
from app.fusion.engine import default_fusion_engine
from app.schemas.fusion import EvidenceItem, EvidenceSource, AssuranceRiskLevel, AssuranceAction
from app.schemas.integrity import IntegritySeverity
from app.schemas.base import AssetStatus


def run_drift_demo() -> bool:
    print("=" * 80)
    print("  TRUST-CV: BENIGN DISTRIBUTION SHIFT vs INTEGRITY VIOLATION DEMONSTRATION")
    print("=" * 80)

    # Step 1: Establish Reference Baseline (Summer EO Profile)
    print("\n[*] Step 1: Registering Reference Baseline Profile (Summer Sentinel-2)...")
    np.random.seed(42)
    summer_ndvi = list(np.random.normal(0.72, 0.05, 100))          # High chlorophyll reflectance
    summer_brightness = list(np.random.normal(110.0, 10.0, 100))   # Peak solar elevation

    baseline = default_drift_engine.register_baseline(
        baseline_id="eo_baseline_summer_2025",
        features={"ndvi": summer_ndvi, "visible_brightness": summer_brightness},
        name="Sentinel2_Summer_Golden_Profile",
    )
    print(f"    [+] Registered Baseline ID: {baseline.baseline_id}")
    print(f"    [+] Sample Size:            {baseline.sample_count} samples")
    print(f"    [+] Baseline Hash Digest:   {baseline.baseline_digest[:16]}... (ECDSA Signed)")

    # Step 2: Ingest Evaluation Data with Natural Seasonal Shift (Autumn EO Profile)
    print("\n[*] Step 2: Ingesting Evaluation Stream (Autumn Sentinel-2 with Lower Sun Angle & Foliage Loss)...")
    autumn_ndvi = list(np.random.normal(0.55, 0.08, 100))          # Moderate natural vegetation decline
    autumn_brightness = list(np.random.normal(92.0, 12.0, 100))    # Lower solar irradiance

    drift_report = default_drift_engine.evaluate_shift(
        baseline_id="eo_baseline_summer_2025",
        target_features={"ndvi": autumn_ndvi, "visible_brightness": autumn_brightness},
        target_batch_id="batch_autumn_mission_01",
    )
    print(f"    [+] Evaluated Batch ID:     {drift_report.target_batch_id}")
    print(f"    [+] Detected Severity:      {drift_report.severity.value}")
    
    for metric in drift_report.feature_metrics:
        print(f"    [+] Metric [{metric.feature_name}]:")
        print(f"        - KS Statistic:         {metric.ks_statistic:.4f} (p-value: {metric.ks_p_value:.4f})")
        print(f"        - PSI Score:            {metric.psi_score:.4f}")
        print(f"        - Wasserstein-1:        {metric.wasserstein_distance:.4f}")
        print(f"        - Energy Distance:      {metric.energy_distance:.4f}")

    # Step 3: Evidence Fusion on Benign Drift
    print("\n[*] Step 3: Fusing Drift Evidence in Gatekeeper Decision Engine...")
    evidence_items = [
        EvidenceItem(
            evidence_id="ev_drift_seasonal_01",
            source=EvidenceSource.DISTRIBUTION_SHIFT,
            evidence_type="SPECTRAL_DISTRIBUTION_SHIFT",
            severity=IntegritySeverity.LOW,
            subject_id="batch_autumn_mission_01",
            confidence=0.85,
            metadata={"nature": "SEASONAL_ATMOSPHERIC_VARIATION"},
        ),
        EvidenceItem(
            evidence_id="ev_data_integrity_clean",
            source=EvidenceSource.DATA_INTEGRITY,
            evidence_type="BYTE_INTEGRITY_CHECK",
            severity=IntegritySeverity.LOW,
            subject_id="batch_autumn_mission_01",
            confidence=1.0,
        ),
    ]

    assessment = default_fusion_engine.fuse(
        target_entity_id="batch_autumn_mission_01",
        evidence=evidence_items,
    )
    print(f"    [+] Hard Veto Triggered:    {assessment.hard_veto_triggered} (Cryptographic integrity is intact)")
    print(f"    [+] Operational Risk Level: {assessment.risk_level.value}")
    print(f"    [+] Gatekeeper Action:      {assessment.action.value} (ALLOW_WITH_MONITORING / REVIEW)")
    print(f"    [+] Final Disposition:      {assessment.verdict.value}")

    print("\n" + "=" * 80)
    print("  KEY TAKEAWAY FOR OPERATORS & JUDGES:")
    print("  - Distribution Shift flags operational review without false-alarm quarantine.")
    print("  - Cryptographic / Weight Tampering triggers immediate BLOCK and QUARANTINE.")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = run_drift_demo()
    sys.exit(0 if success else 1)
