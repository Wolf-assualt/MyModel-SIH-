"""Distribution-Shift Analysis Engine, Cryptographic Baseline Manager & Drift Assurance."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid
# pyrefly: ignore [missing-import]
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
    BaselineReferenceType,
    DistributionShiftReport,
    DriftSeverity,
    DriftType,
    FeatureDriftMetric,
    FeatureSummary,
)


class DistributionShiftEngine:
    """Manages baseline reference distributions, quantifies drift, and categorizes operational vs suspicious shift."""

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
        features: Optional[Dict[str, List[float]]] = None,
        name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        reference_type: BaselineReferenceType = BaselineReferenceType.FEATURE_PROFILE,
        sign_baseline: bool = True,
        image_dir: Optional[Union[str, Path]] = None,
    ) -> BaselineProfile:
        """Create, sign with real ECDSA, and persist a reference baseline profile."""
        if image_dir is not None:
            p = Path(image_dir)
            img_paths = sorted([f for f in p.glob("*") if f.suffix.lower() in (".png", ".jpg", ".jpeg")])
            if not img_paths:
                raise ValueError(f"No images found in image_dir: {image_dir}")
            # pyrefly: ignore [missing-import]
            from PIL import Image
            imgs = [np.array(Image.open(f)) for f in img_paths]
            batch_feats = ImageDistributionExtractor.extract_batch_distributions(imgs)
            features = {k: v.tolist() for k, v in batch_feats.items()}
            reference_type = BaselineReferenceType.REFERENCE_DATASET

        if not features:
            raise ValueError("Baseline features cannot be empty.")

        sample_count = len(next(iter(features.values()))) if features else 0
        feature_summaries: Dict[str, FeatureSummary] = {
            k: ImageDistributionExtractor.compute_feature_summary(v)
            for k, v in features.items()
        }

        # Canonical digest of the baseline definition
        digest_payload = {
            "baseline_id": baseline_id,
            "name": name or f"Baseline {baseline_id}",
            "reference_type": reference_type.value,
            "sample_count": sample_count,
            "metadata": metadata or {},
            "features": {k: [round(float(x), 4) for x in v] for k, v in sorted(features.items())},
        }
        baseline_digest = canonical_json_hash(digest_payload)

        # Real ECDSA SECP256R1 signature
        signature = (
            self.key_manager.sign_hash(baseline_digest)
            if sign_baseline and self.key_manager
            else None
        )

        profile = BaselineProfile(
            baseline_id=baseline_id,
            name=name or f"Baseline {baseline_id}",
            reference_type=reference_type,
            features=features,
            feature_summaries=feature_summaries,
            sample_count=sample_count,
            metadata=metadata or {},
            baseline_digest=baseline_digest,
            signature=signature,
            created_at=datetime.now(timezone.utc),
        )

        # Persist baseline JSON
        filepath = self.baselines_dir / f"{baseline_id}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(profile.model_dump(mode="json")))

        return profile

    def load_baseline_profile(self, baseline_id: str) -> BaselineProfile:
        """Load registered baseline profile from disk."""
        filepath = self.baselines_dir / f"{baseline_id}.json"
        if not filepath.is_file():
            raise FileNotFoundError(f"Baseline profile '{baseline_id}' not found.")

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return BaselineProfile.model_validate(data)

    def load_baseline(self, baseline_id: str) -> Dict[str, List[float]]:
        """Load registered baseline feature vectors from disk."""
        profile = self.load_baseline_profile(baseline_id)
        return profile.features

    def verify_baseline_integrity(self, baseline_id: str) -> Tuple[bool, List[str]]:
        """Cryptographically audit a baseline profile on disk against its canonical digest and signature."""
        discrepancies: List[str] = []
        filepath = self.baselines_dir / f"{baseline_id}.json"
        if not filepath.is_file():
            return False, [f"Baseline file {baseline_id}.json does not exist."]

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        features = data.get("features", {})
        digest_payload = {
            "baseline_id": data.get("baseline_id"),
            "name": data.get("name"),
            "reference_type": data.get("reference_type", BaselineReferenceType.FEATURE_PROFILE.value),
            "sample_count": data.get("sample_count", 0),
            "metadata": data.get("metadata", {}),
            "features": {k: [round(float(x), 4) for x in v] for k, v in sorted(features.items())},
        }
        recomputed_digest = canonical_json_hash(digest_payload)
        stored_digest = data.get("baseline_digest", "")

        if recomputed_digest != stored_digest:
            discrepancies.append(
                f"Baseline digest mismatch: recomputed '{recomputed_digest}' != stored '{stored_digest}'."
            )

        if data.get("signature") and self.key_manager:
            pubkey_pem = self.key_manager.export_public_key_pem().decode("utf-8")
            sig_valid = KeyManager.verify_signature(pubkey_pem, stored_digest, data["signature"])
            if not sig_valid:
                discrepancies.append("Baseline ECDSA signature is invalid.")

        return (len(discrepancies) == 0, discrepancies)

    def evaluate_shift(
        self,
        baseline_id: str,
        target_features: Optional[Dict[str, List[float]]] = None,
        target_batch_id: str = "batch_target",
        threshold: float = 0.25,
        expected_baseline_digest: Optional[str] = None,
        candidate_dir: Optional[Union[str, Path]] = None,
        drift_threshold: Optional[float] = None,
    ) -> DistributionShiftReport:
        """Compare candidate batch distributions against registered reference baseline."""
        # 1. Anti-self-comparison invariant
        if baseline_id == target_batch_id:
            raise ValueError(
                "Self-comparison violation: target dataset cannot be evaluated against itself as baseline."
            )

        eff_threshold = drift_threshold if drift_threshold is not None else threshold

        # 2. Load and verify baseline existence
        profile = self.load_baseline_profile(baseline_id)
        if expected_baseline_digest and profile.baseline_digest != expected_baseline_digest:
            raise ValueError(
                f"Baseline identity mismatch: Digest '{profile.baseline_digest}' does not match expected '{expected_baseline_digest}'."
            )

        if candidate_dir is not None:
            p = Path(candidate_dir)
            img_paths = sorted([f for f in p.glob("*") if f.suffix.lower() in (".png", ".jpg", ".jpeg")])
            if not img_paths:
                raise ValueError(f"No images found in candidate_dir: {candidate_dir}")
            # pyrefly: ignore [missing-import]
            from PIL import Image
            imgs = [np.array(Image.open(f)) for f in img_paths]
            batch_feats = ImageDistributionExtractor.extract_batch_distributions(imgs)
            target_features = {k: v.tolist() for k, v in batch_feats.items()}

        baseline_features = profile.features
        if not target_features:
            raise ValueError("Target features dictionary cannot be empty.")

        feature_metrics: List[FeatureDriftMetric] = []
        drifted_features: List[str] = []
        evidence_records: List[Dict[str, Any]] = []

        # Common feature dimensions
        common_keys = [k for k in baseline_features.keys() if k in target_features]
        if not common_keys:
            raise ValueError("No overlapping feature metrics between baseline and target.")

        for feat_name in common_keys:
            base_arr = np.asarray(baseline_features[feat_name], dtype=np.float64)
            targ_arr = np.asarray(target_features[feat_name], dtype=np.float64)

            ks_dist = compute_ks_distance(base_arr, targ_arr)
            ks_pval = compute_ks_p_value(base_arr, targ_arr, ks_dist)
            psi_val = compute_psi(base_arr, targ_arr)
            wass_val = wasserstein_distance_1d(base_arr, targ_arr)
            energy_val = compute_energy_distance(base_arr, targ_arr)

            b_mean = float(np.mean(base_arr)) if len(base_arr) > 0 else 0.0
            t_mean = float(np.mean(targ_arr)) if len(targ_arr) > 0 else 0.0

            # Combined drift determination: KS distance > eff_threshold or PSI > 0.25
            is_drifted = (ks_dist > eff_threshold) or (psi_val > 0.25)
            if is_drifted:
                drifted_features.append(feat_name)

            explanation = (
                f"{feat_name}: KS={ks_dist:.4f} (p={ks_pval:.4f}), "
                f"PSI={psi_val:.4f}, Wasserstein={wass_val:.4f}, Energy={energy_val:.4f}"
            )

            metric = FeatureDriftMetric(
                feature_name=feat_name,
                baseline_mean=round(b_mean, 4),
                target_mean=round(t_mean, 4),
                drift_score=round(ks_dist, 4),
                ks_distance=round(ks_dist, 4),
                ks_p_value=round(ks_pval, 4),
                psi=round(psi_val, 4),
                wasserstein=round(wass_val, 4),
                energy_distance=round(energy_val, 4),
                is_drifted=is_drifted,
                explanation=explanation,
            )
            feature_metrics.append(metric)

            if is_drifted:
                ev_sev = "CRITICAL" if psi_val > 0.5 or ks_dist > 0.6 else "HIGH"
                evidence_records.append({
                    "evidence_id": f"ev_drift_{uuid.uuid4().hex[:12]}",
                    "source": "DRIFT_ENGINE",
                    "baseline_id": baseline_id,
                    "baseline_digest": profile.baseline_digest,
                    "feature_name": feat_name,
                    "severity": ev_sev,
                    "ks_distance": round(ks_dist, 4),
                    "psi": round(psi_val, 4),
                    "description": f"Distribution drift detected in '{feat_name}': {explanation}",
                })

        overall_drift_score = (
            float(np.mean([m.drift_score for m in feature_metrics]))
            if feature_metrics
            else 0.0
        )
        overall_drift_score = round(overall_drift_score, 4)

        drift_set = set(drifted_features)

        # 3. Classify operational vs suspicious shift
        if overall_drift_score <= threshold and not drifted_features:
            detected_drift_type = DriftType.NO_DRIFT
            severity = DriftSeverity.NO_DRIFT
            status = AssetStatus.ACCEPTED
        elif "sharpness" in drift_set and not ({"brightness", "contrast", "channel_entropy"} & drift_set):
            detected_drift_type = DriftType.SENSOR_DEGRADATION
            severity = DriftSeverity.MILD_DRIFT
            status = AssetStatus.UNDER_REVIEW
        elif ("brightness" in drift_set or "color_temperature" in drift_set or "contrast" in drift_set) and "channel_entropy" not in drift_set and overall_drift_score < 0.60:
            detected_drift_type = DriftType.OPERATIONAL_ENVIRONMENTAL
            severity = DriftSeverity.MILD_DRIFT
            status = AssetStatus.UNDER_REVIEW
        elif "channel_entropy" in drift_set or overall_drift_score >= 0.60:
            detected_drift_type = DriftType.ADVERSARIAL_ANOMALY
            severity = DriftSeverity.CRITICAL_SHIFT
            status = AssetStatus.QUARANTINED
        else:
            detected_drift_type = DriftType.DATASET_DRIFT
            severity = DriftSeverity.SIGNIFICANT_DRIFT
            status = AssetStatus.UNDER_REVIEW

        sample_count = len(next(iter(target_features.values()))) if target_features else 0
        report_id = f"shift_{uuid.uuid4().hex[:12]}"

        report_payload = {
            "report_id": report_id,
            "baseline_id": baseline_id,
            "target_batch_id": target_batch_id,
            "sample_count": sample_count,
            "overall_drift_score": overall_drift_score,
            "detected_drift_type": detected_drift_type.value,
            "severity": severity.value,
            "feature_metrics": [m.model_dump() for m in feature_metrics],
            "affected_features": drifted_features,
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
            severity=severity,
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
            json.dump(report.model_dump(mode="json"), f, indent=2)

        return report

    def list_baselines(self) -> List[Dict[str, Any]]:
        """List all registered baseline profiles."""
        summaries = []
        for fpath in self.baselines_dir.glob("*.json"):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                summaries.append({
                    "baseline_id": data.get("baseline_id"),
                    "name": data.get("name"),
                    "sample_count": data.get("sample_count"),
                    "baseline_digest": data.get("baseline_digest"),
                    "created_at": data.get("created_at"),
                })
            except Exception:
                continue
        return summaries

    def get_report(self, report_id: str) -> Optional[DistributionShiftReport]:
        """Load stored drift report by report ID."""
        filepath = self.reports_dir / f"{report_id}.json"
        if not filepath.exists():
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return DistributionShiftReport.model_validate(data)


# Default singleton instance
default_drift_engine = DistributionShiftEngine()
