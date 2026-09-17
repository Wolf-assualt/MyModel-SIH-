"""Distribution-Shift Analysis Engine and Baseline Manager."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid
import numpy as np

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.drift.stats import compute_ks_distance
from app.schemas.base import AssetStatus
from app.schemas.drift import (
    DistributionShiftReport,
    DriftType,
    FeatureDriftMetric,
)


class DistributionShiftEngine:
    """Manages baseline distributions, quantifies drift, and categorizes shift anomalies."""

    def __init__(self, storage_dir: Optional[Path] = None):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "drift"
        self.baselines_dir = base_dir / "baselines"
        self.reports_dir = base_dir / "reports"
        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def register_baseline(
        self,
        baseline_id: str,
        features: Dict[str, List[float]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist a reference baseline feature profile to disk."""
        if not features:
            raise ValueError("Baseline features cannot be empty.")

        filepath = self.baselines_dir / f"{baseline_id}.json"
        data = {
            "baseline_id": baseline_id,
            "features": features,
            "metadata": metadata or {},
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_baseline(self, baseline_id: str) -> Dict[str, List[float]]:
        """Load registered baseline feature vectors from disk."""
        filepath = self.baselines_dir / f"{baseline_id}.json"
        if not filepath.exists():
            raise FileNotFoundError(f"Baseline '{baseline_id}' does not exist.")

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("features", {})

    def evaluate_shift(
        self,
        baseline_id: str,
        target_features: Dict[str, List[float]],
        target_batch_id: str = "batch_target",
        threshold: float = 0.25,
    ) -> DistributionShiftReport:
        """Compare candidate batch distributions against registered baseline."""
        baseline_features = self.load_baseline(baseline_id)
        if not target_features:
            raise ValueError("Target features dictionary cannot be empty.")

        feature_metrics: List[FeatureDriftMetric] = []
        drifted_features: set[str] = set()

        # Common features between baseline and target
        common_keys = [k for k in baseline_features.keys() if k in target_features]
        if not common_keys:
            raise ValueError("No overlapping feature metrics between baseline and target.")

        for feat_name in common_keys:
            base_arr = np.asarray(baseline_features[feat_name], dtype=np.float64)
            targ_arr = np.asarray(target_features[feat_name], dtype=np.float64)

            ks_dist = compute_ks_distance(base_arr, targ_arr)
            b_mean = float(np.mean(base_arr)) if len(base_arr) > 0 else 0.0
            t_mean = float(np.mean(targ_arr)) if len(targ_arr) > 0 else 0.0
            is_drifted = ks_dist > threshold

            if is_drifted:
                drifted_features.add(feat_name)

            feature_metrics.append(
                FeatureDriftMetric(
                    feature_name=feat_name,
                    baseline_mean=round(b_mean, 4),
                    target_mean=round(t_mean, 4),
                    drift_score=round(ks_dist, 4),
                    is_drifted=is_drifted,
                )
            )

        overall_drift_score = (
            float(np.mean([m.drift_score for m in feature_metrics]))
            if feature_metrics
            else 0.0
        )
        overall_drift_score = round(overall_drift_score, 4)

        # Classify drift type and assign operational asset status
        if overall_drift_score <= threshold and not drifted_features:
            detected_drift_type = DriftType.NO_DRIFT
            status = AssetStatus.ACCEPTED
        elif "sharpness" in drifted_features and not ({"brightness", "contrast", "channel_entropy"} & drifted_features):
            # Sharpness degradation alone indicates optical/sensor blur or lens obstruction
            detected_drift_type = DriftType.SENSOR_DEGRADATION
            status = AssetStatus.UNDER_REVIEW
        elif ("brightness" in drifted_features or "contrast" in drifted_features) and overall_drift_score < 0.65 and "channel_entropy" not in drifted_features:
            # Shift in illumination/contrast denotes operational/environmental variation (e.g. dawn/dusk, fog)
            detected_drift_type = DriftType.OPERATIONAL_ENVIRONMENTAL
            status = AssetStatus.UNDER_REVIEW
        elif "channel_entropy" in drifted_features or overall_drift_score >= 0.65:
            # Extreme divergence or entropy shifts indicate adversarial or unnatural distribution tampering
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
            "target_batch_id": target_batch_id,
            "sample_count": sample_count,
            "overall_drift_score": overall_drift_score,
            "detected_drift_type": detected_drift_type.value,
            "feature_metrics": [m.model_dump() for m in feature_metrics],
            "status": status.value,
        }
        report_digest = canonical_json_hash(report_payload)

        report = DistributionShiftReport(
            report_id=report_id,
            baseline_id=baseline_id,
            target_batch_id=target_batch_id,
            sample_count=sample_count,
            overall_drift_score=overall_drift_score,
            detected_drift_type=detected_drift_type,
            feature_metrics=feature_metrics,
            status=status,
            report_digest=report_digest,
            created_at=datetime.now(timezone.utc),
        )

        # Persist report to disk
        report_path = self.reports_dir / f"{report_id}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2)

        return report

    def get_report(self, report_id: str) -> Optional[DistributionShiftReport]:
        """Load report by report_id from disk."""
        filepath = self.reports_dir / f"{report_id}.json"
        if not filepath.exists():
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return DistributionShiftReport.model_validate(data)


# Default singleton instance
default_drift_engine = DistributionShiftEngine()
