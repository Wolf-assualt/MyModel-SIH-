"""Defense-grade multi-format rendering for TRUST-CV Security Assurance Reports."""
from app.schemas.report import AssuranceReport


class ReportFormatter:
    """Formats AssuranceReport instances into Markdown, JSON, or Executive Summaries."""

    @staticmethod
    def format_markdown(report: AssuranceReport) -> str:
        """Render a defense-grade Markdown document with banners, metrics, and cryptographic proofs."""
        # Findings table rows
        crit_count = report.findings_summary.get("CRITICAL", 0)
        high_count = report.findings_summary.get("HIGH", 0)
        med_count = report.findings_summary.get("MEDIUM", 0)
        low_count = report.findings_summary.get("LOW", 0)

        # Threat narratives bullets
        if report.threat_narratives:
            threats_md = "\n".join(f"- {threat}" for threat in report.threat_narratives)
        else:
            threats_md = "- *No cross-layer threats identified. Verified within acceptable baseline thresholds.*"

        # Limitations bullets
        if report.limitations_and_disclaimers:
            limits_md = "\n".join(f"- {limit}" for limit in report.limitations_and_disclaimers)
        else:
            limits_md = "- *Standard operational assumptions apply.*"

        # Key PEM snippet
        pem_clean = report.signer_public_key_pem.strip()

        lines = [
            "# [RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT]",
            "**SIH26228 — Ministry of Defence (MoD)**  ",
            "*Zero-Trust Computer Vision Integrity Assurance & Evidence Graph*",
            "",
            "---",
            "",
            "## Report Metadata",
            f"- **Report ID**: `{report.report_id}`",
            f"- **Target Asset ID**: `{report.target_asset_id}` (`{report.target_asset_type}`)",
            f"- **Assessment Reference**: `{report.assessment_id}`",
            f"- **Generated At**: `{report.created_at.isoformat()}`",
            "",
            "---",
            "",
            f"### OPERATIONAL VERDICT: {report.overall_verdict.value}",
            "",
            "## Threat & Integrity Metrics Matrix",
            "| Metric | Score | Operational Significance |",
            "| :--- | :--- | :--- |",
            f"| **Composite Risk Score** | `{report.risk_score:.4f}` | 0.0 = Verified Secure; 1.0 = Severely Compromised |",
            f"| **Assurance Confidence** | `{report.confidence_score:.4f}` | Statistical confidence derived from verified evidence breadth |",
            f"| **Layer Coverage Ratio** | `{report.coverage_ratio * 100:.1f}%` | Percentage of foundational assurance layers inspected |",
            "",
            "## Verified Findings Breakdown",
            "| Severity Tier | Incident Count | Actionable Response |",
            "| :--- | :--- | :--- |",
            f"| **CRITICAL** | **{crit_count}** | Immediate Pipeline Halt & Quarantine Mandated |",
            f"| **HIGH** | **{high_count}** | Secondary Verification & Policy Review Required |",
            f"| **MEDIUM** | **{med_count}** | Operational Monitoring & Discrepancy Logging |",
            f"| **LOW** | **{low_count}** | Informational Baseline Recording |",
            "",
            "## Correlated Threat Narratives",
            threats_md,
            "",
            "## Audit Limitations & Operational Disclaimers",
            limits_md,
            "",
            "---",
            "",
            "## Cryptographic Provenance Seal",
            f"- **Canonical Report Digest (SHA-256)**: `{report.report_digest}`",
            f"- **ECDSA SECP256R1 Digital Signature**: `{report.signature}`",
            "- **Signing Authority Public Key (SubjectPublicKeyInfo)**:",
            "```pem",
            pem_clean,
            "```",
            "",
            "---",
            "*RESTRICTED DOCUMENT // NOT TO BE DISCLOSED OUTSIDE DEFENSE ASSURANCE CHANNELS*",
        ]

        return "\n".join(lines)

    @staticmethod
    def format_executive_summary(report: AssuranceReport) -> str:
        """Render a concise plain-text situational briefing summary for commanders."""
        crit = report.findings_summary.get("CRITICAL", 0)
        high = report.findings_summary.get("HIGH", 0)
        med = report.findings_summary.get("MEDIUM", 0)
        low = report.findings_summary.get("LOW", 0)

        primary_threat = (
            report.threat_narratives[0]
            if report.threat_narratives
            else "All pipeline layers operating within verified parameters."
        )

        lines = [
            "================================================================================",
            "                   TRUST-CV EXECUTIVE SECURITY SITUATION BRIEF                  ",
            "================================================================================",
            f"TARGET ASSET       : {report.target_asset_id} ({report.target_asset_type})",
            f"OPERATIONAL VERDICT: {report.overall_verdict.value}",
            f"COMPOSITE RISK     : {report.risk_score:.4f} (Coverage: {report.coverage_ratio * 100:.1f}%)",
            f"FINDINGS TALLY     : CRITICAL: {crit} | HIGH: {high} | MEDIUM: {med} | LOW: {low}",
            f"SITUATION NARRATIVE: {primary_threat}",
            f"CRYPTOGRAPHIC SEAL : {report.report_digest[:16]}...{report.report_digest[-16:]}",
            f"TIMESTAMP (UTC)    : {report.created_at.isoformat()}",
            "================================================================================",
        ]

        return "\n".join(lines)
