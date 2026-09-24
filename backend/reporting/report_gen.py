import json
import html
from typing import Dict, Any
from backend.reporting.finding import ScanSummary

class ReportGenerator:
    """Generates structured JSON and professional executive HTML/PDF security audit reports."""

    @staticmethod
    def generate_json(summary: ScanSummary) -> str:
        return json.dumps(summary.model_dump(), indent=2)

    @staticmethod
    def generate_html_report(summary: ScanSummary) -> str:
        findings_html = ""
        for f in summary.findings:
            sev_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6"
            }.get(f.severity, "#6b7280")

            steps_li = "".join([f"<li>{html.escape(s)}</li>" for s in f.remediation_steps])

            findings_html += f"""
            <div class="finding-card" style="border-left: 5px solid {sev_color};">
                <div class="finding-header">
                    <span class="badge" style="background-color: {sev_color};">{f.severity}</span>
                    <span class="owasp-tag">{html.escape(f.owasp_tag)}</span>
                    <span class="cvss-pill">CVSS {f.cvss_score}</span>
                    <h3 class="finding-title">{html.escape(f.vuln_type)}</h3>
                </div>
                <p class="endpoint"><strong>Target:</strong> <code>{html.escape(f.method)} {html.escape(f.endpoint)}</code></p>
                <div class="section">
                    <h4>Evidence & Proof of Concept</h4>
                    <p>{html.escape(f.evidence)}</p>
                    <pre class="curl-box"><code>{html.escape(f.reproduction_curl)}</code></pre>
                </div>
                <div class="section">
                    <h4>Executive Summary & Business Impact</h4>
                    <p>{html.escape(f.plain_english_summary)}</p>
                    <p style="color: #f87171;"><em>Impact: {html.escape(f.business_impact)}</em></p>
                </div>
                <div class="section">
                    <h4>Developer Remediation Steps</h4>
                    <ul>{steps_li}</ul>
                    {f"<pre class='code-box'><code>{html.escape(f.code_fix_example)}</code></pre>" if f.code_fix_example else ""}
                </div>
            </div>
            """

        agentic_html = ""
        agent_data = summary.ai_risk_overview.get("agentic_chain") if summary.ai_risk_overview else None
        if agent_data:
            steps_items = ""
            for st in agent_data.get("steps", []):
                steps_items += f"""
                <div class="agent-step">
                    <strong>Step {st.get('step_number')}: {html.escape(st.get('title', ''))}</strong>
                    <p><em>Action:</em> {html.escape(st.get('action', ''))}</p>
                    <p><code>{html.escape(st.get('target_endpoint', ''))}</code></p>
                    <p style="color: #60a5fa;">{html.escape(st.get('observation', ''))}</p>
                </div>
                """
            agentic_html = f"""
            <div class="agent-box">
                <h2>Autonomous Pentest Agent: Exploit Chain Verified</h2>
                <p><strong>Objective:</strong> {html.escape(agent_data.get('target_objective', ''))}</p>
                <div class="agent-steps">{steps_items}</div>
                <p style="margin-top: 10px; color: #f87171;"><strong>Impact:</strong> {html.escape(agent_data.get('impact_summary', ''))}</p>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SentinelAPI Zero-Trust Audit Report — {html.escape(summary.scan_id)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{ max-width: 960px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #30363d; padding-bottom: 20px; margin-bottom: 30px; }}
        h1 {{ color: #58a6ff; margin: 0 0 10px 0; font-size: 28px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; text-align: center; }}
        .stat-val {{ font-size: 24px; font-weight: bold; margin-top: 5px; }}
        .crit-text {{ color: #ef4444; }}
        .high-text {{ color: #f97316; }}
        .med-text {{ color: #eab308; }}
        .finding-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 25px; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; color: #fff; }}
        .owasp-tag {{ background: #21262d; border: 1px solid #30363d; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .cvss-pill {{ background: #30363d; padding: 4px 8px; border-radius: 4px; font-size: 12px; color: #e6edf3; }}
        .finding-title {{ margin: 0; font-size: 18px; color: #f0f6fc; }}
        .curl-box, .code-box {{ background: #0b0e14; border: 1px solid #30363d; border-radius: 6px; padding: 12px; overflow-x: auto; color: #38bdf8; font-family: monospace; font-size: 13px; }}
        .agent-box {{ background: #1a162b; border: 1px solid #7c3aed; border-radius: 8px; padding: 20px; margin-bottom: 30px; }}
        .agent-step {{ background: #0f0c1b; border: 1px solid #4c1d95; border-radius: 6px; padding: 12px; margin-top: 10px; }}
        @media print {{ body {{ background: #fff; color: #000; }} .finding-card, .stat-card {{ border-color: #ccc; background: #fafafa; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SentinelAPI Zero-Trust Security Audit</h1>
            <p>Scan ID: <code>{html.escape(summary.scan_id)}</code> | Target: <code>{html.escape(summary.target_url)}</code> | Duration: {summary.duration_seconds}s</p>
            <div class="meta-grid">
                <div class="stat-card"><div>Risk Score</div><div class="stat-val crit-text">{summary.overall_risk_score}/100</div></div>
                <div class="stat-card"><div>Critical Flaws</div><div class="stat-val crit-text">{summary.critical_count}</div></div>
                <div class="stat-card"><div>High Severity</div><div class="stat-val high-text">{summary.high_count}</div></div>
                <div class="stat-card"><div>Total Findings</div><div class="stat-val">{summary.findings_count}</div></div>
            </div>
        </div>

        {agentic_html}

        <h2>Detailed Vulnerability Findings ({len(summary.findings)})</h2>
        {findings_html}
    </div>
</body>
</html>
"""
        return html_content
