"""Training-Data Integrity Engine orchestrating duplicate, quality, label, OOD, and trigger analysis."""
import json
import base64
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash
from app.integrity.detectors import (
    DuplicateDetector,
    LabelInconsistencyDetector,
    QualityDetector,
    OODDetector,
    TriggerCandidateDetector,
    CleanlabLabelQualityDetector,
)
from app.schemas.base import AssetStatus
from app.schemas.dataset import BatchManifest
from app.schemas.integrity import (
    ContributorRisk,
    DatasetIntegrityReport,
    AuditEvent,
    ImageAssessment,
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
        self.quality_detector = QualityDetector()
        self.ood_detector = OODDetector()
        self.trigger_detector = TriggerCandidateDetector()
        self.cleanlab_detector = CleanlabLabelQualityDetector()

    def _preview_data_url(self, file_path: Path) -> Optional[str]:
        try:
            # pyrefly: ignore [missing-import]
            from PIL import Image

            with Image.open(file_path) as image:
                image.thumbnail((240, 180))
                output = BytesIO()
                image.convert("RGB").save(output, format="JPEG", quality=78)
            encoded = base64.b64encode(output.getvalue()).decode("ascii")
            return f"data:image/jpeg;base64,{encoded}"
        except Exception:
            return None

    def _append_audit_events(self, events: list[AuditEvent]) -> None:
        audit_file = Path(settings.DATA_DIR) / "audit" / "image_events.jsonl"
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        with audit_file.open("a", encoding="utf-8") as stream:
            for event in events:
                stream.write(canonical_json_dumps(event.model_dump(mode="json")) + "\n")

    def _previous_hashes(self) -> dict[str, set[str]]:
        audit_file = Path(settings.DATA_DIR) / "audit" / "image_events.jsonl"
        previous: dict[str, set[str]] = {}
        if not audit_file.is_file():
            return previous
        with audit_file.open("r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    event = AuditEvent(**json.loads(line))
                except Exception:
                    continue
                previous.setdefault(event.artifact_id, set()).add(event.sha256_hash)
        return previous

    def _aggregate_contributor_risk(
        self,
        manifest: BatchManifest,
        findings: list[IntegrityFinding],
    ) -> list[ContributorRisk]:
        """Aggregate findings by contributor. Only when contributor identity exists."""
        contributor_id = manifest.contributor_id
        if not contributor_id or contributor_id == "UNKNOWN":
            # Do not produce risk score from fabricated identity
            return []

        severity_dist: dict[str, int] = defaultdict(int)
        finding_types: set[str] = set()
        risk_indicators: list[str] = []

        for f in findings:
            severity_dist[f.severity.value] += 1
            finding_types.add(f.check_type.value)

        if severity_dist.get("CRITICAL", 0) > 0:
            risk_indicators.append("CRITICAL_FINDINGS_PRESENT")
        if severity_dist.get("HIGH", 0) > 3:
            risk_indicators.append("HIGH_FINDING_CONCENTRATION")

        return [ContributorRisk(
            contributor_id=contributor_id,
            sample_count=len(manifest.samples),
            finding_count=len(findings),
            finding_types=sorted(finding_types),
            severity_distribution=dict(severity_dist),
            risk_indicators=risk_indicators,
        )]

    def scan(
        self,
        manifest: BatchManifest,
        duplicate_threshold: int = 4,
        trigger_detection_enabled: bool = True,
        ood_reference_stats: Optional[dict] = None,
    ) -> DatasetIntegrityReport:
        """Run all integrity checks and synthesize an actionable integrity report."""
        findings: list[IntegrityFinding] = []

        # 1. Exact & Near Duplicate Detection
        findings.extend(self.duplicate_detector.detect(manifest.samples, duplicate_threshold))

        # 2. Label Inconsistency + Missing Labels + Malformed Annotations
        findings.extend(self.label_detector.detect(manifest.samples))
        # Cleanlab Confident Learning Label Quality & Noise Detection
        findings.extend(self.cleanlab_detector.detect(manifest.samples))

        # 3. Quality Detection (variance, aspect ratio, corruption)
        findings.extend(self.quality_detector.detect(manifest.samples))

        # 4. OOD Detection (reference-based only; UNAVAILABLE without reference)
        # The OOD detector returns empty findings when reference_stats is None.
        # The scan pipeline (scan.py) reports UNAVAILABLE for this component.
        findings.extend(self.ood_detector.detect(manifest.samples, ood_reference_stats))

        # 5. Trigger Candidate Detection
        if trigger_detection_enabled:
            findings.extend(self.trigger_detector.detect(manifest.samples))

        findings_by_sample: dict[str, list[IntegrityFinding]] = {sample.sample_id: [] for sample in manifest.samples}
        for finding in findings:
            for sample_id in finding.sample_ids:
                findings_by_sample.setdefault(sample_id, []).append(finding)

        image_results: list[ImageAssessment] = []
        audit_events: list[AuditEvent] = []
        previous_hashes = self._previous_hashes()
        for sample in manifest.samples:
            sample_findings = findings_by_sample.get(sample.sample_id, [])
            changed_fingerprint = bool(previous_hashes.get(sample.sample_id) and sample.sha256_hash not in previous_hashes[sample.sample_id])
            critical = [
                finding for finding in sample_findings
                if finding.severity in (IntegritySeverity.CRITICAL, IntegritySeverity.HIGH)
                and (
                    finding.check_type.value != "TRIGGER_CANDIDATE"
                    or finding.details.get("isolated_sample") is True
                    or len(finding.sample_ids) <= 2
                )
            ]
            medium = [finding for finding in sample_findings if finding.severity == IntegritySeverity.MEDIUM]
            if critical:
                result = "POISONED / ALTERED"
                integrity_status = "FAIL"
                trust_status = "UNTRUSTED"
                action = "QUARANTINE"
            elif changed_fingerprint or medium or any(
                finding.check_type.value not in ("NEAR_DUPLICATE",) for finding in sample_findings
            ):
                result = "SUSPICIOUS"
                integrity_status = "REVIEW REQUIRED"
                trust_status = "UNTRUSTED"
                action = "QUARANTINE"
            else:
                result = "REAL / CLEAN"
                integrity_status = "PASS"
                trust_status = "VERIFIED"
                action = "ALLOW"

            score = max((finding.metric_score for finding in sample_findings), default=None)
            image_results.append(ImageAssessment(
                sample_id=sample.sample_id,
                file_name=Path(sample.file_path).name,
                sha256_hash=sample.sha256_hash,
                result=result,
                integrity_status=integrity_status,
                trust_status=trust_status,
                anomaly_score=score,
                evidence=(
                    (["SHA-256 fingerprint changed since a previous upload."] if changed_fingerprint else [])
                    + [finding.description for finding in sample_findings]
                ),
                action=action,
                preview_data_url=self._preview_data_url(Path(sample.file_path)),
            ))
            audit_events.extend([
                AuditEvent(
                    timestamp=manifest.created_at,
                    artifact_id=sample.sample_id,
                    sha256_hash=sample.sha256_hash,
                    detection_result=result,
                    integrity_status=integrity_status,
                    reason="; ".join(image_results[-1].evidence) or "Uploaded artifact verified by integrity pipeline.",
                    action="UPLOADED",
                    contributor_id=manifest.contributor_id,
                ),
                AuditEvent(
                    timestamp=manifest.created_at,
                    artifact_id=sample.sample_id,
                    sha256_hash=sample.sha256_hash,
                    detection_result=result,
                    integrity_status=integrity_status,
                    reason="; ".join(image_results[-1].evidence) or "No integrity findings detected.",
                    action="VERIFIED",
                    contributor_id=manifest.contributor_id,
                ),
            ])
        self._append_audit_events(audit_events)

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

        # Phase 3: Contributor Risk Aggregation
        contributor_risks = self._aggregate_contributor_risk(manifest, findings)

        # Construct Report
        report_data = {
            "batch_id": manifest.batch_id,
            "total_samples_analyzed": len(manifest.samples),
            "findings_count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings],
            "overall_health_score": health_score,
            "recommendation": recommendation.value,
            "image_results": [image.model_dump(mode="json") for image in image_results],
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
            image_results=image_results,
            audit_events=audit_events,
            contributor_risks=contributor_risks,
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
