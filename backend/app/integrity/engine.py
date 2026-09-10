"""Training-Data Integrity Engine orchestrating duplicate, quality, label, and backdoor analysis."""
import json
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash
from app.integrity.detectors import (
    DuplicateDetector,
    LabelInconsistencyDetector,
    QualityAndOODDetector,
    TriggerBackdoorDetector,
)
from app.schemas.base import AssetStatus
from app.schemas.dataset import BatchManifest
from app.schemas.integrity import (
    DatasetIntegrityReport,
    IntegrityFinding,
    IntegritySeverity,
)

PENALTY_WEIGHTS = {
    IntegritySeverity.CRITICAL: 0.30,
    IntegritySeverity.HIGH: 0.15,
    IntegritySeverity.MEDIUM: 0.05,
    IntegritySeverity.LOW: 0.02,
}


class DataIntegrityEngine:
    """Executes multi-dimensional integrity scans over ingested dataset batch manifests."""

    def __init__(self, reports_dir: Optional[Path] = None):
        if reports_dir:
            self.reports_dir = Path(reports_dir)
        else:
            self.reports_dir = Path(settings.DATA_DIR) / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.duplicate_detector = DuplicateDetector()
        self.label_detector = LabelInconsistencyDetector()
        self.quality_detector = QualityAndOODDetector()
        self.trigger_detector = TriggerBackdoorDetector()

    def scan(
        self,
        manifest: BatchManifest,
        duplicate_threshold: int = 4,
        trigger_detection_enabled: bool = True,
    ) -> DatasetIntegrityReport:
        """Run all integrity checks and synthesize an actionable integrity report."""
        findings: list[IntegrityFinding] = []

        # 1. Exact & Near Duplicate Detection
        findings.extend(self.duplicate_detector.detect(manifest.samples, duplicate_threshold))

        # 2. Label Inconsistency Detection
        findings.extend(self.label_detector.detect(manifest.samples))

        # 3. Quality, Variance & Out-Of-Distribution Detection
        findings.extend(self.quality_detector.detect(manifest.samples))

        # 4. Trigger & Backdoor Detection
        if trigger_detection_enabled:
            findings.extend(self.trigger_detector.detect(manifest.samples))

        # Compute Health Score
        health_score = 1.0
        for f in findings:
            penalty = PENALTY_WEIGHTS.get(f.severity, 0.05)
            health_score -= penalty

        health_score = round(max(0.0, min(1.0, health_score)), 4)

        # Disposition Recommendation
        if health_score >= 0.85:
            recommendation = AssetStatus.ACCEPTED
        elif health_score >= 0.60:
            recommendation = AssetStatus.UNDER_REVIEW
        else:
            recommendation = AssetStatus.QUARANTINED

        # Construct Report
        report_data = {
            "batch_id": manifest.batch_id,
            "total_samples_analyzed": len(manifest.samples),
            "findings_count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings],
            "overall_health_score": health_score,
            "recommendation": recommendation.value,
        }
        report_digest = canonical_json_hash(report_data)

        report = DatasetIntegrityReport(
            batch_id=manifest.batch_id,
            total_samples_analyzed=len(manifest.samples),
            findings_count=len(findings),
            findings=findings,
            overall_health_score=health_score,
            recommendation=recommendation,
            report_digest=report_digest,
        )

        # Persist report canonically to disk
        report_file = self.reports_dir / f"integrity_{manifest.batch_id}.json"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(report.model_dump(mode="json")))

        return report

    def load_report(self, batch_id: str) -> Optional[DatasetIntegrityReport]:
        """Load an existing integrity report from disk by batch_id."""
        report_file = self.reports_dir / f"integrity_{batch_id}.json"
        if not report_file.is_file():
            return None

        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return DatasetIntegrityReport(**data)


default_integrity_engine = DataIntegrityEngine()
