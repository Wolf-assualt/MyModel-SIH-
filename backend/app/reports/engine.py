"""Defense-Grade Forensic Security Assurance Report Generation and Verification Engine.

Phase 12: Comprehensive cross-domain forensic report synthesis, cryptographic sealing,
multi-format export, and zero-trust verification.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash
from app.crypto.signer import KeyManager, default_key_manager
from app.fusion.engine import EvidenceFusionEngine, default_fusion_engine
from app.graph.engine import EvidenceGraphEngine, default_graph_engine
from app.reports.formatter import ReportFormatter
from app.schemas.base import AssetStatus
from app.schemas.fusion import AssuranceAction, AssuranceRiskLevel, EvidenceItem, FusedAssessment
from app.schemas.report import (
    AssuranceReport,
    ExportReportResponse,
    ForensicCryptographicProofs,
    ReportFormat,
    ReportSectionOverview,
    VerifyReportResponse,
)


class AssuranceReportEngine:
    """Generates, seals, formats, exports, and cryptographically verifies defense forensic assurance reports."""

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        fusion_engine: Optional[EvidenceFusionEngine] = None,
        graph_engine: Optional[EvidenceGraphEngine] = None,
    ):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "reports" / "assurance"
        self.storage_dir = Path(base_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir = self.storage_dir / "exports"
        self.exports_dir.mkdir(parents=True, exist_ok=True)

        self.fusion_engine = fusion_engine or default_fusion_engine
        self.graph_engine = graph_engine or default_graph_engine

    def generate_report(
        self,
        target_asset_id: str,
        target_asset_type: str = "MODEL",
        assessment: Optional[FusedAssessment] = None,
        assessment_id: Optional[str] = None,
        key_manager: Optional[KeyManager] = None,
        include_lineage: bool = True,
        include_blast_radius: bool = True,
        include_limitations: bool = True,
    ) -> AssuranceReport:
        """Synthesize an immutable, digitally signed comprehensive AssuranceReport."""
        # 1. Resolve or generate Fused Assessment
        assmt = assessment
        if not assmt and assessment_id:
            assmt = self.fusion_engine.get_assessment(assessment_id)

        if not assmt:
            # Look for existing registered evidence for target asset or create baseline assessment
            existing_ev = [
                e for e in self.fusion_engine.list_evidence()
                if e.subject_id == target_asset_id or e.related_model_id == target_asset_id or e.related_dataset_id == target_asset_id
            ]
            assmt = self.fusion_engine.fuse(
                target_entity_id=target_asset_id,
                evidence=existing_ev,
                strict_subject_binding=False,
            )

        # 2. Tally findings summary by severity and categorize by domain
        findings_summary: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        dataset_findings: List[Dict[str, Any]] = []
        model_findings: List[Dict[str, Any]] = []
        behavioral_findings: List[Dict[str, Any]] = []
        inference_findings: List[Dict[str, Any]] = []
        drift_findings: List[Dict[str, Any]] = []

        for item in assmt.raw_evidence:
            sev_key = item.severity.value
            findings_summary[sev_key] = findings_summary.get(sev_key, 0) + 1
            dumped_ev = item.model_dump(mode="json")

            src = item.source.value
            if "DATA" in src:
                dataset_findings.append(dumped_ev)
            elif "MODEL" in src or "CRYPTO" in src:
                model_findings.append(dumped_ev)
            elif "BEHAVIOUR" in src:
                behavioral_findings.append(dumped_ev)
            elif "INFERENCE" in src:
                inference_findings.append(dumped_ev)
            elif "DISTRIBUTION" in src or "DRIFT" in src:
                drift_findings.append(dumped_ev)

        # 3. Generate Section Overviews
        section_overviews: List[ReportSectionOverview] = [
            ReportSectionOverview(
                layer_name="Dataset & Training Data Integrity",
                status=AssetStatus.QUARANTINED if any(f.get("severity") == "CRITICAL" for f in dataset_findings) else (AssetStatus.UNDER_REVIEW if dataset_findings else AssetStatus.ACCEPTED),
                risk_contribution=0.35 if dataset_findings else 0.0,
                findings_count=len(dataset_findings),
                key_observations=[f.get("description", "") for f in dataset_findings[:3]],
            ),
            ReportSectionOverview(
                layer_name="Model Identity & Weight Integrity",
                status=AssetStatus.QUARANTINED if any(f.get("severity") == "CRITICAL" for f in model_findings) else (AssetStatus.UNDER_REVIEW if model_findings else AssetStatus.ACCEPTED),
                risk_contribution=0.35 if model_findings else 0.0,
                findings_count=len(model_findings),
                key_observations=[f.get("description", "") for f in model_findings[:3]],
            ),
            ReportSectionOverview(
                layer_name="Behavioral Fingerprint & Probes",
                status=AssetStatus.UNDER_REVIEW if behavioral_findings else AssetStatus.ACCEPTED,
                risk_contribution=0.15 if behavioral_findings else 0.0,
                findings_count=len(behavioral_findings),
                key_observations=[f.get("description", "") for f in behavioral_findings[:3]],
            ),
            ReportSectionOverview(
                layer_name="Runtime Inference DNA & Nonce Integrity",
                status=AssetStatus.QUARANTINED if any(f.get("severity") == "CRITICAL" for f in inference_findings) else (AssetStatus.UNDER_REVIEW if inference_findings else AssetStatus.ACCEPTED),
                risk_contribution=0.10 if inference_findings else 0.0,
                findings_count=len(inference_findings),
                key_observations=[f.get("description", "") for f in inference_findings[:3]],
            ),
            ReportSectionOverview(
                layer_name="Distribution Shift & Drift Analysis",
                status=AssetStatus.UNDER_REVIEW if drift_findings else AssetStatus.ACCEPTED,
                risk_contribution=0.05 if drift_findings else 0.0,
                findings_count=len(drift_findings),
                key_observations=[f.get("description", "") for f in drift_findings[:3]],
            ),
        ]

        # 4. Quarantine Records
        quar_records = [
            q for q in self.fusion_engine.list_quarantines()
            if q.subject_id == target_asset_id or target_asset_id in q.evidence_ids
        ]

        # 5. Provenance Lineage & Blast Radius
        upstream_nodes: List[Any] = []
        blast_report = None
        if include_lineage and target_asset_id in self.graph_engine.nodes:
            upstream_nodes = self.graph_engine.trace_upstream(target_asset_id)
        if include_blast_radius and target_asset_id in self.graph_engine.nodes:
            try:
                blast_report = self.graph_engine.calculate_blast_radius(target_asset_id)
            except Exception:
                pass

        # 6. Operational Disclaimers & Limitations
        limitations: List[str] = []
        if include_limitations:
            if assmt.coverage.missing_sources:
                missing_str = ", ".join(s.value for s in assmt.coverage.missing_sources)
                limitations.append(
                    f"Partial layer coverage: [{missing_str}] were uninspected in this evaluation."
                )
            limitations.append(
                "Integrity and drift findings are empirical measurements bounded by camera sensor resolution, dynamic range, and baseline calibration."
            )
            limitations.append(
                "Zero-trust mathematical provenance assumes the integrity and confidentiality of the asymmetric root signing key."
            )
            limitations.append(
                "Downstream blast radius reflects operational dependency exposure; it does not claim that all downstream assets are compromised."
            )

        # 7. Canonical Report Digest
        report_id = f"rep_{uuid.uuid4().hex[:12]}"
        digest_payload = {
            "report_id": report_id,
            "target_asset_id": target_asset_id,
            "target_asset_type": target_asset_type,
            "assessment_id": assmt.assessment_id,
            "overall_verdict": assmt.verdict.value,
            "gatekeeper_action": assmt.action.value,
            "risk_score": assmt.risk_score,
            "risk_level": assmt.risk_level.value,
            "confidence_score": assmt.confidence_score,
            "coverage_ratio": assmt.coverage.coverage_ratio,
            "hard_veto_triggered": assmt.hard_veto_triggered,
            "findings_summary": findings_summary,
        }
        report_digest = canonical_json_hash(digest_payload)

        # 8. Cryptographic Proofs and Digital Signature
        km = key_manager or default_key_manager
        signature = km.sign_hash(report_digest)
        signer_public_key_pem = km.export_public_key_pem().decode("utf-8")

        crypto_proofs = ForensicCryptographicProofs(
            canonical_report_digest=report_digest,
            ecdsa_signature=signature,
            signer_public_key_pem=signer_public_key_pem,
            assessment_digest=assmt.assessment_digest,
            model_binary_sha256=assmt.raw_evidence[0].metrics.get("binary_sha256") if assmt.raw_evidence else None,
            graph_digest=self.graph_engine.export_graph(sign=False).graph_digest if len(self.graph_engine.nodes) > 0 else None,
        )

        created_at = datetime.now(timezone.utc)

        report = AssuranceReport(
            report_id=report_id,
            target_asset_id=target_asset_id,
            target_asset_type=target_asset_type,
            assessment_id=assmt.assessment_id,
            overall_verdict=assmt.verdict,
            gatekeeper_action=assmt.action,
            risk_score=assmt.risk_score,
            risk_level=assmt.risk_level,
            confidence_score=assmt.confidence_score,
            coverage_ratio=assmt.coverage.coverage_ratio,
            hard_veto_triggered=assmt.hard_veto_triggered,
            veto_reasons=assmt.veto_reasons,
            findings_summary=findings_summary,
            threat_narratives=assmt.correlated_findings,
            section_overviews=section_overviews,
            dataset_findings=dataset_findings,
            model_findings=model_findings,
            behavioral_findings=behavioral_findings,
            inference_findings=inference_findings,
            drift_findings=drift_findings,
            quarantine_records=quar_records,
            upstream_lineage=upstream_nodes,
            downstream_blast_radius=blast_report,
            limitations_and_disclaimers=limitations,
            cryptographic_proofs=crypto_proofs,
            report_digest=report_digest,
            signature=signature,
            signer_public_key_pem=signer_public_key_pem,
            created_at=created_at,
        )

        # 9. Persist Report JSON
        report_path = self.storage_dir / f"{report_id}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2)

        return report

    def verify_report(self, report: AssuranceReport) -> VerifyReportResponse:
        """Cryptographically audit an assurance report for tampering and valid digital signature."""
        discrepancies: List[str] = []

        # 1. Recompute canonical digest
        expected_digest_payload = {
            "report_id": report.report_id,
            "target_asset_id": report.target_asset_id,
            "target_asset_type": report.target_asset_type,
            "assessment_id": report.assessment_id,
            "overall_verdict": report.overall_verdict.value,
            "gatekeeper_action": report.gatekeeper_action.value,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level.value,
            "confidence_score": report.confidence_score,
            "coverage_ratio": report.coverage_ratio,
            "hard_veto_triggered": report.hard_veto_triggered,
            "findings_summary": report.findings_summary,
        }
        recomputed_digest = canonical_json_hash(expected_digest_payload)

        digest_match = (recomputed_digest == report.report_digest)
        if not digest_match:
            discrepancies.append(
                f"Report digest mismatch: recomputed '{recomputed_digest}' does not match record '{report.report_digest}'."
            )

        # 2. Verify ECDSA digital signature
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
            verified_at=datetime.now(timezone.utc),
        )

    def export_report_to_file(
        self,
        report_id: str,
        export_format: ReportFormat = ReportFormat.JSON_MANIFEST,
        output_path: Optional[Path] = None,
    ) -> ExportReportResponse:
        """Export a forensic report to disk in the specified presentation format."""
        report = self.get_report(report_id)
        if not report:
            raise FileNotFoundError(f"Report '{report_id}' not found.")

        ext_map = {
            ReportFormat.JSON_MANIFEST: "json",
            ReportFormat.MARKDOWN: "md",
            ReportFormat.EXECUTIVE_SUMMARY: "txt",
            ReportFormat.HTML: "html",
        }
        ext = ext_map.get(export_format, "txt")
        target_file = output_path or (self.exports_dir / f"{report_id}.{ext}")

        if export_format == ReportFormat.JSON_MANIFEST:
            content = canonical_json_dumps(report.model_dump(mode="json"))
        elif export_format == ReportFormat.MARKDOWN:
            content = ReportFormatter.format_markdown(report)
        elif export_format == ReportFormat.EXECUTIVE_SUMMARY:
            content = ReportFormatter.format_executive_summary(report)
        elif export_format == ReportFormat.HTML:
            content = ReportFormatter.format_html(report)
        else:
            content = ReportFormatter.format_markdown(report)

        target_file.write_text(content, encoding="utf-8")
        file_bytes = target_file.stat().st_size
        export_digest = canonical_json_hash({"content": content})

        return ExportReportResponse(
            report_id=report_id,
            format=export_format,
            export_path=str(target_file),
            file_size_bytes=file_bytes,
            export_digest=export_digest,
        )

    def get_report(self, report_id: str) -> Optional[AssuranceReport]:
        """Retrieve stored report by report_id."""
        report_path = self.storage_dir / f"{report_id}.json"
        if not report_path.is_file():
            return None
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return AssuranceReport.model_validate(data)

    def list_reports(self) -> List[AssuranceReport]:
        """List all generated forensic assurance reports in storage."""
        reports = []
        for file in self.storage_dir.glob("*.json"):
            if file.name == "exports":
                continue
            try:
                with open(file, "r", encoding="utf-8") as f:
                    reports.append(AssuranceReport.model_validate(json.load(f)))
            except Exception:
                pass
        return sorted(reports, key=lambda r: r.created_at, reverse=True)


# Default singleton instance
default_report_engine = AssuranceReportEngine()
