"""Defense-Grade Security Assurance Report Generation and Verification Engine."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, List, Optional
import uuid

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.crypto.signer import KeyManager, default_key_manager
from app.schemas.fusion import FusedAssessment
from app.schemas.report import AssuranceReport, VerifyReportResponse


class AssuranceReportEngine:
    """Generates, seals, and cryptographically verifies defense security assurance reports."""

    def __init__(self, storage_dir: Optional[Path] = None):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "reports" / "assurance"
        self.storage_dir = base_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        target_asset_id: str,
        target_asset_type: str,
        assessment: FusedAssessment,
        key_manager: Optional[KeyManager] = None,
        include_limitations: bool = True,
    ) -> AssuranceReport:
        """Synthesize an immutable, digitally signed AssuranceReport from an evidence assessment."""
        # 1. Tally findings summary by severity
        findings_summary: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in assessment.raw_evidence:
            sev_key = item.severity.value
            findings_summary[sev_key] = findings_summary.get(sev_key, 0) + 1

        # 2. Derive limitations & operational disclaimers
        limitations: List[str] = []
        if include_limitations:
            if assessment.coverage.missing_sources:
                missing_str = ", ".join(s.value for s in assessment.coverage.missing_sources)
                limitations.append(
                    f"Uninspected assurance layers: [{missing_str}]. Risk scores represent partial assurance."
                )
            limitations.append(
                "Integrity and drift metrics are bounded by operational camera sensor dynamics and calibration."
            )
            limitations.append(
                "Zero-trust provenance assurance assumes asymmetric root signing key confidentiality."
            )

        # 3. Canonical report digest over core metrics and verdict
        digest_payload = {
            "target_asset_id": target_asset_id,
            "target_asset_type": target_asset_type,
            "assessment_id": assessment.assessment_id,
            "overall_verdict": assessment.verdict.value,
            "risk_score": assessment.risk_score,
            "confidence_score": assessment.confidence_score,
            "coverage_ratio": assessment.coverage.coverage_ratio,
            "findings_summary": findings_summary,
        }
        report_digest = canonical_json_hash(digest_payload)

        # 4. Asymmetric ECDSA SECP256R1 digital signature
        km = key_manager or default_key_manager
        signature = km.sign_hash(report_digest)
        signer_public_key_pem = km.export_public_key_pem().decode("utf-8")

        report_id = f"report_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc)

        report = AssuranceReport(
            report_id=report_id,
            target_asset_id=target_asset_id,
            target_asset_type=target_asset_type,
            assessment_id=assessment.assessment_id,
            overall_verdict=assessment.verdict,
            risk_score=assessment.risk_score,
            confidence_score=assessment.confidence_score,
            coverage_ratio=assessment.coverage.coverage_ratio,
            findings_summary=findings_summary,
            threat_narratives=assessment.correlated_findings,
            limitations_and_disclaimers=limitations,
            report_digest=report_digest,
            signature=signature,
            signer_public_key_pem=signer_public_key_pem,
            created_at=created_at,
        )

        # 5. Persist report JSON to storage
        report_path = self.storage_dir / f"{report_id}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2)

        return report

    @staticmethod
    def verify_report(report: AssuranceReport) -> VerifyReportResponse:
        """Cryptographically audit an assurance report for tampering and valid digital signature."""
        discrepancies: List[str] = []

        # 1. Recompute canonical digest
        expected_digest_payload = {
            "target_asset_id": report.target_asset_id,
            "target_asset_type": report.target_asset_type,
            "assessment_id": report.assessment_id,
            "overall_verdict": report.overall_verdict.value,
            "risk_score": report.risk_score,
            "confidence_score": report.confidence_score,
            "coverage_ratio": report.coverage_ratio,
            "findings_summary": report.findings_summary,
        }
        recomputed_digest = canonical_json_hash(expected_digest_payload)

        digest_match = (recomputed_digest == report.report_digest)
        if not digest_match:
            discrepancies.append(
                f"Report digest mismatch: recomputed '{recomputed_digest}' does not match record '{report.report_digest}'."
            )

        # 2. Verify ECDSA SECP256R1 digital signature
        signature_valid = KeyManager.verify_signature(
            public_key_pem=report.signer_public_key_pem,
            digest_hex=report.report_digest,
            signature_hex=report.signature,
        )
        if not signature_valid:
            discrepancies.append(
                "ECDSA SECP256R1 digital signature verification failed against provided signer public key."
            )

        is_valid = digest_match and signature_valid

        return VerifyReportResponse(
            is_valid=is_valid,
            digest_match=digest_match,
            signature_valid=signature_valid,
            discrepancies=discrepancies,
        )

    def get_report(self, report_id: str) -> Optional[AssuranceReport]:
        """Retrieve stored report by report_id."""
        report_path = self.storage_dir / f"{report_id}.json"
        if not report_path.exists():
            return None
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return AssuranceReport.model_validate(data)


# Default singleton instance
default_report_engine = AssuranceReportEngine()
