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

    @staticmethod
    def format_html(report: AssuranceReport) -> str:
        """Render a standalone air-gapped HTML forensic report for briefing or auditing."""
        crit_count = report.findings_summary.get("CRITICAL", 0)
        high_count = report.findings_summary.get("HIGH", 0)
        med_count = report.findings_summary.get("MEDIUM", 0)
        low_count = report.findings_summary.get("LOW", 0)

        if report.threat_narratives:
            threats_html = "\n".join(f"<li>{threat}</li>" for threat in report.threat_narratives)
        else:
            threats_html = "<li>*No cross-layer threats identified.*</li>"

        if report.limitations_and_disclaimers:
            limits_html = "\n".join(f"<li>{limit}</li>" for limit in report.limitations_and_disclaimers)
        else:
            limits_html = "<li>*Standard operational assumptions apply.*</li>"

        pem_clean = report.signer_public_key_pem.strip()
        verdict_class = report.overall_verdict.value.lower()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TRUST-CV Forensic Report - {report.report_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #1a1a1a; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }}
        h1 {{ color: #8b0000; border-bottom: 2px solid #8b0000; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 24px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        th, td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
        th {{ background: #f0f0f0; font-weight: 600; }}
        .seal {{ background: #f9f9f9; padding: 12px; border: 1px solid #ddd; font-family: monospace; font-size: 12px; word-break: break-all; }}
        .footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #ccc; color: #666; font-size: 12px; }}
        ul {{ padding-left: 20px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>[RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT]</h1>
    <p><strong>SIH26228 — Ministry of Defence (MoD)</strong><br>
    *Zero-Trust Computer Vision Integrity Assurance &amp; Evidence Graph*</p>
    <hr>
    <h2>Report Metadata</h2>
    <table>
        <tr><td><strong>Report ID</strong></td><td><code>{report.report_id}</code></td></tr>
        <tr><td><strong>Target Asset ID</strong></td><td><code>{report.target_asset_id}</code> ({report.target_asset_type})</td></tr>
        <tr><td><strong>Assessment Reference</strong></td><td><code>{report.assessment_id}</code></td></tr>
        <tr><td><strong>Generated At</strong></td><td><code>{report.created_at.isoformat()}</code></td></tr>
    </table>
    <hr>
    <h2>OPERATIONAL VERDICT: {report.overall_verdict.value}</h2>
    <h2>Threat &amp; Integrity Metrics Matrix</h2>
    <table>
        <tr><th>Metric</th><th>Score</th><th>Operational Significance</th></tr>
        <tr><td><strong>Composite Risk Score</strong></td><td><code>{report.risk_score:.4f}</code></td><td>0.0 = Verified Secure; 1.0 = Severely Compromised</td></tr>
    </table>
    <h2>Assurance Layer Status Overview</h2>
    <table>
        <tr><th>Layer</th><th>Status</th><th>Risk Contribution</th></tr>
        <tr><td><strong>Assurance Confidence</strong></td><td><code>{report.confidence_score:.4f}</code></td><td>Statistical confidence derived from verified evidence breadth</td></tr>
        <tr><td><strong>Layer Coverage Ratio</strong></td><td><code>{report.coverage_ratio * 100:.1f}%</code></td><td>Percentage of foundational assurance layers inspected</td></tr>
    </table>
    <h2>Verified Findings Breakdown</h2>
    <table>
        <tr><th>Severity Tier</th><th>Incident Count</th><th>Actionable Response</th></tr>
        <tr><td><strong>CRITICAL</strong></td><td><strong>{crit_count}</strong></td><td>Immediate Pipeline Halt &amp; Quarantine Mandated</td></tr>
        <tr><td><strong>HIGH</strong></td><td><strong>{high_count}</strong></td><td>Secondary Verification &amp; Policy Review Required</td></tr>
        <tr><td><strong>MEDIUM</strong></td><td><strong>{med_count}</strong></td><td>Operational Monitoring &amp; Discrepancy Logging</td></tr>
        <tr><td><strong>LOW</strong></td><td><strong>{low_count}</strong></td><td>Informational Baseline Recording</td></tr>
    </table>
    <h2>Correlated Threat Narratives</h2>
    <ul>{threats_html}</ul>
    <h2>Audit Limitations &amp; Operational Disclaimers</h2>
    <ul>{limits_html}</ul>
    <hr>
    <h2>Cryptographic Provenance Seal</h2>
    <div class="seal">
        <strong>Canonical Report Digest (SHA-256):</strong> <code>{report.report_digest}</code><br>
        <strong>ECDSA SECP256R1 Digital Signature:</strong> <code>{report.signature}</code><br>
        <strong>Signing Authority Public Key (SPKI):</strong>
        <pre>{pem_clean}</pre>
    </div>
    <hr>
    <p class="footer"><em>RESTRICTED DOCUMENT // NOT TO BE DISCLOSED OUTSIDE DEFENSE ASSURANCE CHANNELS</em></p>
</div>
</body>
</html>"""
        return html
        return "\n".join(lines)
