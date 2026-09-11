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
        """Render a standalone, air-gapped defense-grade HTML forensic report."""
        crit = report.findings_summary.get("CRITICAL", 0)
        high = report.findings_summary.get("HIGH", 0)
        med = report.findings_summary.get("MEDIUM", 0)
        low = report.findings_summary.get("LOW", 0)

        verdict_color = "#10b981" if report.overall_verdict.value == "ACCEPT" else ("#ef4444" if "QUARANTINE" in report.overall_verdict.value or report.overall_verdict.value == "REJECT" else "#f59e0b")

        threat_items = "".join(f"<li>{t}</li>" for t in report.threat_narratives) if report.threat_narratives else "<li><em>No cross-layer anomalies detected.</em></li>"
        disclaimer_items = "".join(f"<li>{d}</li>" for d in report.limitations_and_disclaimers) if report.limitations_and_disclaimers else "<li><em>Standard operational parameters apply.</em></li>"

        overview_rows = ""
        for sec in report.section_overviews:
            status_color = "#10b981" if sec.status.value == "ACCEPTED" else ("#ef4444" if sec.status.value == "QUARANTINED" else "#f59e0b")
            overview_rows += f"""
            <tr>
                <td><strong>{sec.layer_name}</strong></td>
                <td><span style="color: {status_color}; font-weight: bold;">{sec.status.value}</span></td>
                <td>{sec.findings_count}</td>
                <td>{sec.risk_contribution:.2f}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TRUST-CV Forensic Report - {report.report_id}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --border: #374151;
            --accent: #3b82f6;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
        }}
        .header h1 {{
            margin: 0;
            color: var(--accent);
            font-size: 1.5rem;
            letter-spacing: 0.05em;
        }}
        .header p {{
            margin: 0.25rem 0 0 0;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        .verdict-badge {{
            display: inline-block;
            background: {verdict_color};
            color: #ffffff;
            font-weight: bold;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            margin: 1rem 0;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }}
        .metric-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }}
        .metric-card .val {{
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--text-primary);
        }}
        .metric-card .lbl {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.25rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.875rem;
        }}
        th, td {{
            padding: 0.75rem;
            border: 1px solid var(--border);
            text-align: left;
        }}
        th {{
            background: var(--bg-card);
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
        }}
        .seal-box {{
            background: #0d1117;
            border: 1px dashed #30363d;
            border-radius: 6px;
            padding: 1rem;
            font-family: monospace;
            font-size: 0.8rem;
            color: #58a6ff;
            word-break: break-all;
            margin-top: 1.5rem;
        }}
        ul {{
            padding-left: 1.25rem;
        }}
        li {{
            margin-bottom: 0.25rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RESTRICTED // TRUST-CV SECURITY ASSURANCE REPORT</h1>
            <p>SIH26228 — Ministry of Defence | Zero-Trust Computer Vision Integrity Assurance Platform</p>
        </div>

        <div>
            <strong>Report ID:</strong> <code>{report.report_id}</code> |
            <strong>Target Asset:</strong> <code>{report.target_asset_id}</code> ({report.target_asset_type}) |
            <strong>Generated:</strong> {report.created_at.isoformat()}
        </div>

        <div>
            <span class="verdict-badge">OPERATIONAL VERDICT: {report.overall_verdict.value}</span>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="val">{report.risk_score:.4f}</div>
                <div class="lbl">Composite Risk Score</div>
            </div>
            <div class="metric-card">
                <div class="val">{report.confidence_score:.4f}</div>
                <div class="lbl">Assurance Confidence</div>
            </div>
            <div class="metric-card">
                <div class="val">{report.coverage_ratio * 100:.1f}%</div>
                <div class="lbl">Layer Coverage</div>
            </div>
            <div class="metric-card">
                <div class="val">C:{crit} H:{high} M:{med} L:{low}</div>
                <div class="lbl">Findings Breakdown</div>
            </div>
        </div>

        <h3>Assurance Layer Status Overview</h3>
        <table>
            <thead>
                <tr>
                    <th>Assurance Layer</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Risk Contribution</th>
                </tr>
            </thead>
            <tbody>
                {overview_rows}
            </tbody>
        </table>

        <h3>Threat Corroboration & Anomalies</h3>
        <ul>
            {threat_items}
        </ul>

        <h3>Operational Disclaimers & Audit Limitations</h3>
        <ul>
            {disclaimer_items}
        </ul>

        <h3>Cryptographic Provenance Seal</h3>
        <div class="seal-box">
            <div><strong>Canonical Digest:</strong> {report.report_digest}</div>
            <div style="margin-top: 0.5rem;"><strong>Digital Signature (ECDSA):</strong> {report.signature}</div>
        </div>
    </div>
</body>
</html>"""
        return html

