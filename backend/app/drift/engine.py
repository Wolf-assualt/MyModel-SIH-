"""Distribution-Shift Analysis Engine and Baseline Manager for CV Integrity Assurance."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import uuid
import numpy as np

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash
from app.crypto.signer import KeyManager, default_key_manager
from app.drift.extractor import ImageDistributionExtractor
from app.drift.stats import (
    compute_energy_distance,
    compute_ks_distance,
    compute_ks_p_value,
    compute_psi,
    wasserstein_distance_1d,
)
from app.schemas.base import AssetStatus
from app.schemas.drift import (
    BaselineProfile,
    DistributionShiftReport,
    DriftSeverity,
    DriftType,
    FeatureDriftMetric,
)


class DistributionShiftEngine:
    """Manages baseline distributions, quantifies drift metrics, and categorizes shift anomalies."""

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        key_manager: Optional[KeyManager] = None,
    ):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "drift"
        self.baselines_dir = base_dir / "baselines"
        self.reports_dir = base_dir / "reports"
        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.key_manager = key_manager or default_key_manager

    def register_baseline(
        self,
        baseline_id: str,
        features: Dict[str, List[float]],
        name: str = "approved_baseline",
        metadata: Optional[Dict[str, Any]] = None,
        sign: bool = True,
    ) -> BaselineProfile:
        """Persist a cryptographically signed reference baseline feature profile to disk."""
        if not features:
            raise ValueError("Baseline features cannot be empty.")

        # Compute summary moments for each feature
        summaries = {
            k: ImageDistributionExtractor.compute_feature_summary(v)
            for k, v in features.items()
        }
        sample_count = max((len(v) for v in features.values()), default=0)

        # Canonical baseline profile payload for cryptographic binding
        profile_core = {
            "baseline_id": baseline_id,
            "name": name,
            "sample_count": sample_count,
            "features": {k: [float(x) for x in v] for k, v in sorted(features.items())},
            "feature_summaries": {k: s.model_dump() for k, s in sorted(summaries.items())},
            "metadata": metadata or {},
        }
        baseline_digest = canonical_json_hash(profile_core)
        signature = self.key_manager.sign_hash(baseline_digest) if sign else None

        profile = BaselineProfile(
            baseline_id=baseline_id,
            name=name,
            sample_count=sample_count,
            features=features,
            feature_summaries=summaries,
            baseline_digest=baseline_digest,
            signature=signature,
            created_at=datetime.now(timezone.utc),
            metadata=metadata or {},
        )

        filepath = self.baselines_dir / f"{baseline_id}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(profile.model_dump(mode="json")))

        return profile

    def load_baseline_profile(self, baseline_id: str) -> Optional[BaselineProfile]:
        """Load registered BaselineProfile by baseline_id."""
        filepath = self.baselines_dir / f"{baseline_id}.json"
        if not filepath.is_file():
            return None

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        return BaselineProfile.model_validate(data)

    def load_baseline(self, baseline_id: str) -> Dict[str, List[float]]:
        """Load registered baseline raw feature vectors from disk."""
        profile = self.load_baseline_profile(baseline_id)
        if not profile:
            raise FileNotFoundError(f"Baseline '{baseline_id}' does not exist.")
        return profile.features

    def list_baselines(self) -> List[BaselineProfile]:
        """List all registered baseline profiles in storage."""
        profiles: List[BaselineProfile] = []
        for p in self.baselines_dir.glob("*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                profiles.append(BaselineProfile.model_validate(data))
            except Exception:
                continue
        return profiles

    def verify_baseline_integrity(self, baseline_id: str, public_key_pem: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Verify baseline canonical digest and ECDSA digital signature."""
        profile = self.load_baseline_profile(baseline_id)
        if not profile:
            return False, [f"Baseline '{baseline_id}' not found."]

        discrepancies: List[str] = []
        profile_core = {
            "baseline_id": profile.baseline_id,
            "name": profile.name,
            "sample_count": profile.sample_count,
            "features": {k: [float(x) for x in v] for k, v in sorted(profile.features.items())},
            "feature_summaries": {k: s.model_dump() for k, s in sorted(profile.feature_summaries.items())},
            "metadata": profile.metadata,
        }
        recomputed_digest = canonical_json_hash(profile_core)
        if recomputed_digest != profile.baseline_digest:
            discrepancies.append(
                f"Baseline digest mismatch: recomputed '{recomputed_digest}' != record '{profile.baseline_digest}'."
            )

        if profile.signature:
            pubkey = public_key_pem or self.key_manager.export_public_key_pem().decode("utf-8")
            valid_sig = KeyManager.verify_signature(pubkey, profile.baseline_digest, profile.signature)
            if not valid_sig:
                discrepancies.append("Baseline ECDSA digital signature is invalid.")

        return len(discrepancies) == 0, discrepancies

    def evaluate_shift(
        self,
        baseline_id: str,
        target_features: Dict[str, List[float]],
        target_batch_id: str = "batch_target",
        threshold: float = 0.25,
        expected_baseline_digest: Optional[str] = None,
    ) -> DistributionShiftReport:
        """Compare candidate batch distributions against registered baseline."""
        profile = self.load_baseline_profile(baseline_id)
        if not profile:
            raise FileNotFoundError(f"Baseline '{baseline_id}' does not exist.")

        # Defense against baseline identity mismatch
        if expected_baseline_digest and profile.baseline_digest != expected_baseline_digest:
            raise ValueError(
                f"Baseline identity mismatch: requested expected digest '{expected_baseline_digest}' "
                f"does not match stored baseline digest '{profile.baseline_digest}'."
            )

        if not target_features:
            raise ValueError("Target features dictionary cannot be empty.")

        baseline_features = profile.features
        common_keys = [k for k in baseline_features.keys() if k in target_features]
        if not common_keys:
            raise ValueError("No overlapping feature metrics between baseline and target.")

        feature_metrics: List[FeatureDriftMetric] = []
        drifted_features: List[str] = []
        evidence_records: List[Dict[str, Any]] = []

        for feat_name in common_keys:
            base_arr = np.asarray(baseline_features[feat_name], dtype=np.float64)
            targ_arr = np.asarray(target_features[feat_name], dtype=np.float64)

            # 1. 2-Sample Kolmogorov-Smirnov Test
            ks_stat = compute_ks_distance(base_arr, targ_arr)
            ks_p_val = compute_ks_p_value(base_arr, targ_arr, ks_stat)

            # 2. Population Stability Index (PSI)
            psi_score = compute_psi(base_arr, targ_arr)

            # 3. Wasserstein-1 Distance (Earth Mover's Distance)
            wass_dist = wasserstein_distance_1d(base_arr, targ_arr)

            # 4. Energy Distance
            energy_dist = compute_energy_distance(base_arr, targ_arr)

            b_mean = float(np.mean(base_arr)) if len(base_arr) > 0 else 0.0
            b_std = float(np.std(base_arr)) if len(base_arr) > 0 else 0.0
            t_mean = float(np.mean(targ_arr)) if len(targ_arr) > 0 else 0.0
            t_std = float(np.std(targ_arr)) if len(targ_arr) > 0 else 0.0

            # Composite feature drift score: balanced blend of KS and normalized PSI
            # PSI >= 0.25 is significant drift; KS >= 0.25 is significant divergence
            composite_score = float(max(ks_stat, min(1.0, psi_score / 0.5)))
            drift_score = round(composite_score, 4)

            # Severity tiering per feature
            if drift_score < 0.10:
                feat_severity = DriftSeverity.NO_DRIFT
            elif drift_score < 0.25:
                feat_severity = DriftSeverity.MILD_DRIFT
            elif drift_score < 0.50:
                feat_severity = DriftSeverity.SIGNIFICANT_DRIFT
            else:
                feat_severity = DriftSeverity.CRITICAL_SHIFT

            is_drifted = drift_score > threshold or ks_stat > threshold

            if is_drifted:
                drifted_features.append(feat_name)

            # Explainable diagnostic narrative
            pct_change = ((t_mean - b_mean) / (abs(b_mean) + 1e-6)) * 100.0
            explanation = (
                f"{feat_name}: mean {b_mean:.2f}->{t_mean:.2f} ({pct_change:+.1f}%), "
                f"PSI={psi_score:.4f}, KS={ks_stat:.4f} (p={ks_p_val:.3e}), "
                f"Wasserstein={wass_dist:.4f}, Energy={energy_dist:.4f}"
            )

            metric = FeatureDriftMetric(
                feature_name=feat_name,
                baseline_mean=round(b_mean, 4),
                baseline_std=round(b_std, 4),
                target_mean=round(t_mean, 4),
                target_std=round(t_std, 4),
                drift_score=drift_score,
                wasserstein_distance=round(wass_dist, 4),
                ks_statistic=round(ks_stat, 4),
                ks_p_value=round(ks_p_val, 6),
                psi_score=round(psi_score, 4),
                energy_distance=round(energy_dist, 4),
                severity=feat_severity,
                is_drifted=is_drifted,
                explanation=explanation,
            )
            feature_metrics.append(metric)

            # Generate structured evidence object for drifted features
            if is_drifted:
                evidence_records.append({
                    "evidence_id": str(uuid.uuid4()),
                    "type": "FEATURE_DISTRIBUTION_DRIFT",
                    "source": "DRIFT_ENGINE",
                    "feature_name": feat_name,
                    "baseline_id": baseline_id,
                    "baseline_digest": profile.baseline_digest,
                    "target_batch_id": target_batch_id,
                    "severity": "CRITICAL" if feat_severity == DriftSeverity.CRITICAL_SHIFT else "HIGH" if feat_severity == DriftSeverity.SIGNIFICANT_DRIFT else "MEDIUM",
                    "drift_score": drift_score,
                    "psi_score": round(psi_score, 4),
                    "ks_statistic": round(ks_stat, 4),
                    "ks_p_value": round(ks_p_val, 6),
                    "wasserstein_distance": round(wass_dist, 4),
                    "energy_distance": round(energy_dist, 4),
                    "description": explanation,
                })

        overall_drift_score = (
            float(np.mean([m.drift_score for m in feature_metrics]))
            if feature_metrics
            else 0.0
        )
        overall_drift_score = round(overall_drift_score, 4)

        # Classify overall severity
        if overall_drift_score < 0.10 and not drifted_features:
            severity = DriftSeverity.NO_DRIFT
        elif overall_drift_score < 0.25:
            severity = DriftSeverity.MILD_DRIFT
        elif overall_drift_score < 0.50:
            severity = DriftSeverity.SIGNIFICANT_DRIFT
        else:
            severity = DriftSeverity.CRITICAL_SHIFT

        # Classify root cause drift type and operational asset status
        drifted_set = set(drifted_features)
        if severity == DriftSeverity.NO_DRIFT:
            detected_drift_type = DriftType.NO_DRIFT
            status = AssetStatus.ACCEPTED
        elif "sharpness" in drifted_set and not ({"brightness", "contrast", "channel_entropy"} & drifted_set):
            # Sharpness degradation alone indicates optical/sensor blur or lens obstruction
            detected_drift_type = DriftType.SENSOR_DEGRADATION
            status = AssetStatus.UNDER_REVIEW
        elif ("brightness" in drifted_set or "contrast" in drifted_set) and overall_drift_score < 0.65 and "channel_entropy" not in drifted_set:
            # Shift in illumination/contrast denotes operational/environmental variation (e.g. dawn/dusk, fog)
            detected_drift_type = DriftType.OPERATIONAL_ENVIRONMENTAL
            status = AssetStatus.UNDER_REVIEW
        elif "channel_entropy" in drifted_set or overall_drift_score >= 0.65 or severity == DriftSeverity.CRITICAL_SHIFT:
            # Extreme divergence or entropy collapse indicates adversarial or unnatural distribution tampering
            detected_drift_type = DriftType.ADVERSARIAL_ANOMALY
            status = AssetStatus.QUARANTINED
        else:
            detected_drift_type = DriftType.OPERATIONAL_ENVIRONMENTAL
            status = AssetStatus.UNDER_REVIEW

        sample_count = len(next(iter(target_features.values()))) if target_features else 0
        report_id = f"shift_{uuid.uuid4().hex[:12]}"

        # Canonical report hash
        report_payload = {
            "report_id": report_id,
            "baseline_id": baseline_id,
            "baseline_digest": profile.baseline_digest,
            "target_batch_id": target_batch_id,
            "sample_count": sample_count,
            "overall_drift_score": overall_drift_score,
            "severity": severity.value,
            "detected_drift_type": detected_drift_type.value,
            "feature_metrics": [m.model_dump() for m in feature_metrics],
            "affected_features": drifted_features,
            "status": status.value,
        }
        report_digest = canonical_json_hash(report_payload)

        report = DistributionShiftReport(
            report_id=report_id,
            baseline_id=baseline_id,
            baseline_digest=profile.baseline_digest,
            target_batch_id=target_batch_id,
            sample_count=sample_count,
            overall_drift_score=overall_drift_score,
            severity=severity,
            detected_drift_type=detected_drift_type,
            feature_metrics=feature_metrics,
            affected_features=drifted_features,
            evidence_records=evidence_records,
            status=status,
            report_digest=report_digest,
            created_at=datetime.now(timezone.utc),
        )

        # Persist report to disk
        report_path = self.reports_dir / f"{report_id}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(report.model_dump(mode="json")))

        return report

    def get_report(self, report_id: str) -> Optional[DistributionShiftReport]:
        """Load report by report_id from disk."""
        filepath = self.reports_dir / f"{report_id}.json"
        if not filepath.is_file():
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "baseline_digest" not in data:
            data["baseline_digest"] = "0" * 64
        return DistributionShiftReport.model_validate(data)

    def list_reports(self) -> List[DistributionShiftReport]:
        """Load all reports from disk ordered by created timestamp descending."""
        reports = []
        if self.reports_dir.exists():
            for filepath in self.reports_dir.glob("*.json"):
                rep = self.get_report(filepath.stem)
                if rep:
                    reports.append(rep)
        reports.sort(key=lambda r: getattr(r, "created_at", datetime.now(timezone.utc)), reverse=True)
        return reports


# Default singleton instance
default_drift_engine = DistributionShiftEngine()

