"""Aggregates findings from all modules and renders JSON + Markdown + HTML reports."""
from __future__ import annotations
import json as _json
import datetime
from collections import Counter
from pathlib import Path
from typing import List
from .models import Finding, Severity


SEVERITY_CSS_COLOR = {
    Severity.CRITICAL: "#e53e3e",
    Severity.HIGH:     "#dd6b20",
    Severity.MEDIUM:   "#d69e2e",
    Severity.LOW:      "#3182ce",
    Severity.INFO:     "#718096",
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH:     "[HIGH]",
    Severity.MEDIUM:   "[MEDIUM]",
    Severity.LOW:      "[LOW]",
    Severity.INFO:     "[INFO]",
}

_SEV_ORDER = list(reversed(list(Severity)))   # CRITICAL -> INFO


class Report:
    def __init__(self, findings: List[Finding], target: str = "localhost"):
        self.findings = sorted(findings, key=lambda f: -f.severity.value)
        self.target = target
        self.generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def summary_counts(self) -> dict:
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    # -------------------------------------------------------------------------
    # JSON
    # -------------------------------------------------------------------------

    def to_json(self, path: str) -> None:
        payload = {
            "target": self.target,
            "generated_at": self.generated_at,
            "summary": self.summary_counts(),
            "findings": [f.to_dict() for f in self.findings],
        }
        Path(path).write_text(_json.dumps(payload, indent=2), encoding="utf-8")

    # -------------------------------------------------------------------------
    # Markdown
    # -------------------------------------------------------------------------

    def to_markdown(self, path: str) -> None:
        counts = self.summary_counts()
        lines = [
            "# Vulnerability Assessment Report",
            "",
            f"**Target:** {self.target}  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Total findings:** {len(self.findings)}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|---|---|",
        ]
        for sev in _SEV_ORDER:
            lines.append(f"| {SEVERITY_LABEL[sev]} {sev.name} | {counts[sev.name]} |")

        lines += ["", "## Findings", ""]
        if not self.findings:
            lines.append("No findings recorded.")

        for f in self.findings:
            lines.append(
                f"### {SEVERITY_LABEL[f.severity]} [{f.severity.name}] {f.title}"
            )
            lines.append("")
            lines.append(f"- **Module:** {f.module}")
            lines.append(f"- **Check ID:** {f.check_id}")
            if f.cve_refs:
                lines.append(f"- **CVE refs:** {', '.join(f.cve_refs)}")
            if f.cis_refs:
                lines.append(f"- **CIS/STIG refs:** {', '.join(f.cis_refs)}")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            lines.append("")
            if f.evidence:
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
            lines.append("---")
            lines.append("")

        Path(path).write_text("\n".join(lines), encoding="utf-8")

    # -------------------------------------------------------------------------
    # HTML  (Chart.js severity pie + module bar chart)
    # -------------------------------------------------------------------------

    def to_html(self, path: str) -> None:
        """Self-contained HTML report with Chart.js severity pie and module bar charts."""
        counts = self.summary_counts()

        def badge(sev: Severity) -> str:
            c = SEVERITY_CSS_COLOR[sev]
            return (
                f'<span style="background:{c};color:#fff;border-radius:4px;'
                f'padding:2px 8px;font-size:.82em;font-weight:700">{sev.name}</span>'
            )

        def esc(s: str) -> str:
            return (
                s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;")
            )

        # Chart data
        pie_sevs   = [s for s in _SEV_ORDER if counts[s.name] > 0]
        pie_labels = _json.dumps([s.name for s in pie_sevs])
        pie_data   = _json.dumps([counts[s.name] for s in pie_sevs])
        pie_colors = _json.dumps([SEVERITY_CSS_COLOR[s] for s in pie_sevs])

        mod_counts  = Counter(f.module for f in self.findings)
        bar_labels  = _json.dumps(list(mod_counts.keys()))
        bar_data    = _json.dumps(list(mod_counts.values()))
        bar_colors  = _json.dumps(["#4299e1"] * len(mod_counts))

        # Summary table
        summary_rows = "".join(
            f"<tr><td>{badge(sev)}</td>"
            f"<td><strong>{counts[sev.name]}</strong></td></tr>"
            for sev in _SEV_ORDER
        )

        # Finding cards
        cards = []
        for f in self.findings:
            c = SEVERITY_CSS_COLOR[f.severity]
            refs = ""
            if f.cve_refs:
                refs += f"<p><strong>CVE refs:</strong> {esc(', '.join(f.cve_refs))}</p>"
            if f.cis_refs:
                refs += (
                    f"<p><strong>CIS/STIG refs:</strong> "
                    f"{esc(', '.join(f.cis_refs))}</p>"
                )
            evidence_block = ""
            if f.evidence:
                evidence_block = (
                    f"<details><summary style='cursor:pointer;color:#4a5568;"
                    f"font-size:.9em'>Show evidence</summary>"
                    f"<pre style='background:#f4f4f4;padding:10px;border-radius:4px;"
                    f"overflow-x:auto;margin-top:8px'>{esc(f.evidence)}</pre>"
                    f"</details>"
                )
            remediation_block = ""
            if f.remediation:
                remediation_block = (
                    f"<div style='background:#f0fff4;border-left:3px solid #48bb78;"
                    f"padding:8px 12px;margin-top:8px;border-radius:0 4px 4px 0'>"
                    f"<strong>Remediation:</strong> {esc(f.remediation)}</div>"
                )
            cards.append(
                f'<div class="card" style="border-left:4px solid {c}">'
                f'<h3 style="margin:0 0 6px 0;font-size:1em">'
                f'{badge(f.severity)} {esc(f.title)}</h3>'
                f'<p style="color:#718096;font-size:.82em;margin:0 0 8px 0">'
                f'Module: <code>{esc(f.module)}</code> &nbsp;|&nbsp; '
                f'Check: <code>{esc(f.check_id)}</code></p>'
                f'{refs}'
                f'<p style="margin:6px 0">{esc(f.description)}</p>'
                f'{evidence_block}{remediation_block}</div>'
            )

        findings_html = (
            "\n".join(cards) if cards else
            "<p style='color:#718096'>No findings recorded.</p>"
        )

        html = (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '  <meta charset="UTF-8"/>\n'
            '  <meta name="viewport" content="width=device-width,initial-scale=1"/>\n'
            f"  <title>VulnScan Report - {esc(self.target)}</title>\n"
            "  <script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>\n"
            "  <style>\n"
            "    *{box-sizing:border-box;margin:0;padding:0}\n"
            "    body{font-family:system-ui,-apple-system,sans-serif;background:#f0f4f8;color:#2d3748}\n"
            "    .topbar{background:linear-gradient(135deg,#1a202c,#2d3748);color:#fff;padding:20px 32px}\n"
            "    .topbar h1{font-size:1.3em;font-weight:700}\n"
            "    .topbar .meta{font-size:.82em;color:#a0aec0;margin-top:4px}\n"
            "    .container{max-width:1100px;margin:0 auto;padding:24px}\n"
            "    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}\n"
            "    .panel{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);padding:20px}\n"
            "    .panel h2{font-size:.78em;font-weight:700;margin-bottom:14px;color:#4a5568;"
            "text-transform:uppercase;letter-spacing:.06em}\n"
            "    table{border-collapse:collapse;width:100%}\n"
            "    td,th{padding:7px 12px;text-align:left;border-bottom:1px solid #edf2f7;font-size:.9em}\n"
            "    th{background:#f7fafc;font-weight:600;color:#4a5568;font-size:.78em;text-transform:uppercase}\n"
            "    .card{background:#fff;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.07);"
            "padding:16px 20px;margin-bottom:12px;transition:box-shadow .15s}\n"
            "    .card:hover{box-shadow:0 3px 8px rgba(0,0,0,.12)}\n"
            "    pre{white-space:pre-wrap;word-break:break-all;font-size:.83em;line-height:1.5}\n"
            "    code{background:#edf2f7;padding:1px 5px;border-radius:3px;font-size:.88em;font-family:monospace}\n"
            "    .chart-wrap{position:relative;height:220px}\n"
            "    @media(max-width:680px){.grid2{grid-template-columns:1fr}}\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            '<div class="topbar">\n'
            "  <div>\n"
            "    <h1>VulnScan - Vulnerability Assessment Report</h1>\n"
            '    <div class="meta">\n'
            f"      Target: <strong>{esc(self.target)}</strong> &nbsp;|&nbsp;\n"
            f"      Generated: {esc(self.generated_at)} &nbsp;|&nbsp;\n"
            f"      Total findings: <strong>{len(self.findings)}</strong>\n"
            "    </div>\n"
            "  </div>\n"
            "</div>\n"
            '\n<div class="container">\n'
            '\n  <div class="grid2">\n'
            '    <div class="panel">\n'
            "      <h2>Severity Summary</h2>\n"
            "      <table>\n"
            "        <tr><th>Severity</th><th>Count</th></tr>\n"
            f"        {summary_rows}\n"
            "      </table>\n"
            "    </div>\n"
            '    <div class="panel">\n'
            "      <h2>Severity Distribution</h2>\n"
            '      <div class="chart-wrap"><canvas id="pieChart"></canvas></div>\n'
            "    </div>\n"
            "  </div>\n"
            '\n  <div class="panel" style="margin-bottom:20px">\n'
            "    <h2>Findings by Module</h2>\n"
            '    <div class="chart-wrap" style="height:180px">'
            '<canvas id="barChart"></canvas></div>\n'
            "  </div>\n"
            '\n  <div class="panel">\n'
            "    <h2>Findings</h2>\n"
            '    <div style="margin-top:14px">\n'
            f"      {findings_html}\n"
            "    </div>\n"
            "  </div>\n"
            "\n</div>\n"
            "\n<script>\n"
            "(function() {\n"
            "  new Chart(document.getElementById('pieChart'), {\n"
            "    type: 'doughnut',\n"
            "    data: {\n"
            f"      labels: {pie_labels},\n"
            f"      datasets: [{{ data: {pie_data}, backgroundColor: {pie_colors}, borderWidth: 2 }}]\n"
            "    },\n"
            "    options: {\n"
            "      responsive: true, maintainAspectRatio: false,\n"
            "      plugins: { legend: { position: 'right', labels: { font: { size: 11 } } } }\n"
            "    }\n"
            "  });\n"
            "  new Chart(document.getElementById('barChart'), {\n"
            "    type: 'bar',\n"
            "    data: {\n"
            f"      labels: {bar_labels},\n"
            "      datasets: [{\n"
            "        label: 'Findings',\n"
            f"        data: {bar_data},\n"
            f"        backgroundColor: {bar_colors},\n"
            "        borderRadius: 4\n"
            "      }]\n"
            "    },\n"
            "    options: {\n"
            "      responsive: true, maintainAspectRatio: false,\n"
            "      plugins: { legend: { display: false } },\n"
            "      scales: {\n"
            "        y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 11 } } },\n"
            "        x: { ticks: { font: { size: 11 } } }\n"
            "      }\n"
            "    }\n"
            "  });\n"
            "})();\n"
            "</script>\n"
            "</body>\n"
            "</html>\n"
        )
        Path(path).write_text(html, encoding="utf-8")
