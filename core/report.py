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
    def __init__(self, findings: List[Finding], target: str = "localhost", timings: dict = None):
        self.findings = sorted(findings, key=lambda f: -f.severity.value)
        self.target = target
        self.generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.timings = timings or {}
        self.total_time = sum(self.timings.values()) if self.timings else 0.0

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
            "scan_duration_sec": round(self.total_time, 2),
            "module_timings": {k: round(v, 2) for k, v in self.timings.items()},
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
        counts = self.summary_counts()

        def badge(sev: Severity) -> str:
            c = SEVERITY_CSS_COLOR[sev]
            return (
                f'<span class="sev-badge" data-sev="{sev.name}" style="background:{c};color:#fff;border-radius:4px;'
                f'padding:2px 8px;font-size:.82em;font-weight:700">{sev.name}</span>'
            )

        def esc(s: str) -> str:
            return (
                str(s).replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;")
            )

        # Risk Score Gauge
        avg_risk = 0
        if self.findings:
            avg_risk = int(sum(f.risk_score for f in self.findings) / len(self.findings))
        risk_color = "#48bb78"
        if avg_risk > 70:
            risk_color = "#e53e3e"
        elif avg_risk > 40:
            risk_color = "#d69e2e"

        # Chart data
        pie_sevs   = [s for s in _SEV_ORDER if counts[s.name] > 0]
        pie_labels = _json.dumps([s.name for s in pie_sevs])
        pie_data   = _json.dumps([counts[s.name] for s in pie_sevs])
        pie_colors = _json.dumps([SEVERITY_CSS_COLOR[s] for s in pie_sevs])

        mod_counts  = Counter(f.module for f in self.findings)
        bar_labels  = _json.dumps(list(mod_counts.keys()))
        bar_data    = _json.dumps(list(mod_counts.values()))
        bar_colors  = _json.dumps(["#4299e1"] * len(mod_counts))

        # Timing HTML
        timing_html = ""
        if self.total_time > 0:
            timing_html = f"Scan duration: <strong>{self.total_time:.1f}s</strong>"

        # Finding cards
        cards = []
        for f in self.findings:
            c = SEVERITY_CSS_COLOR[f.severity]
            refs = ""
            if f.cve_refs:
                refs += f"<p><strong>CVE refs:</strong> {esc(', '.join(f.cve_refs))}</p>"
            if f.cis_refs:
                refs += f"<p><strong>CIS/STIG refs:</strong> {esc(', '.join(f.cis_refs))}</p>"
            
            evidence_block = ""
            if f.evidence:
                evidence_block = (
                    f"<details><summary style='cursor:pointer;color:#4a5568;font-size:.9em'>Show evidence</summary>"
                    f"<pre style='background:#f4f4f4;padding:10px;border-radius:4px;overflow-x:auto;margin-top:8px'>{esc(f.evidence)}</pre>"
                    f"</details>"
                )
            remediation_block = ""
            if f.remediation:
                remediation_block = (
                    f"<div style='background:#f0fff4;border-left:3px solid #48bb78;padding:8px 12px;margin-top:8px;border-radius:0 4px 4px 0'>"
                    f"<strong>Remediation:</strong> {esc(f.remediation)}</div>"
                )
            
            cards.append(
                f'<div class="card finding-card" data-severity="{f.severity.name}" data-category="{esc(f.category)}" style="border-left:4px solid {c}">'
                f'<div style="display:flex;justify-content:space-between;align-items:flex-start;">'
                f'<h3 style="margin:0 0 6px 0;font-size:1.1em">{badge(f.severity)} {esc(f.title)}</h3>'
                f'<span style="background:#edf2f7;color:#4a5568;padding:2px 8px;border-radius:12px;font-size:0.8em;font-weight:600">Risk: {f.risk_score}</span>'
                f'</div>'
                f'<p style="color:#718096;font-size:.85em;margin:0 0 8px 0">'
                f'Category: <strong>{esc(f.category)}</strong> &nbsp;|&nbsp; '
                f'Module: <code>{esc(f.module)}</code> &nbsp;|&nbsp; '
                f'Check: <code>{esc(f.check_id)}</code></p>'
                f'{refs}'
                f'<p class="finding-desc" style="margin:6px 0">{esc(f.description)}</p>'
                f'{evidence_block}{remediation_block}</div>'
            )

        findings_html = "\n".join(cards) if cards else "<p style='color:#718096'>No findings recorded.</p>"

        # Filters
        filter_buttons = "".join(
            f'<button class="filter-btn" data-filter="{sev.name}" style="background:{SEVERITY_CSS_COLOR[sev]}">{sev.name} ({counts[sev.name]})</button>'
            for sev in _SEV_ORDER if counts[sev.name] > 0
        )

        html = (
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
            "  <meta charset='UTF-8'/>\n  <meta name='viewport' content='width=device-width,initial-scale=1'/>\n"
            f"  <title>VulnScan Report - {esc(self.target)}</title>\n"
            "  <script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>\n"
            "  <style>\n"
            "    *{box-sizing:border-box;margin:0;padding:0}\n"
            "    body{font-family:system-ui,-apple-system,sans-serif;background:#f0f4f8;color:#2d3748}\n"
            "    .topbar{background:linear-gradient(135deg,#1a202c,#2d3748);color:#fff;padding:20px 32px}\n"
            "    .topbar h1{font-size:1.3em;font-weight:700}\n"
            "    .topbar .meta{font-size:.85em;color:#a0aec0;margin-top:8px}\n"
            "    .container{max-width:1100px;margin:0 auto;padding:24px}\n"
            "    .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-bottom:20px}\n"
            "    .panel{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);padding:20px}\n"
            "    .panel h2{font-size:.85em;font-weight:700;margin-bottom:14px;color:#4a5568;text-transform:uppercase;letter-spacing:.06em}\n"
            "    .card{background:#fff;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.07);padding:16px 20px;margin-bottom:12px;transition:box-shadow .15s}\n"
            "    .card:hover{box-shadow:0 3px 8px rgba(0,0,0,.12)}\n"
            "    pre{white-space:pre-wrap;word-break:break-all;font-size:.83em;line-height:1.5}\n"
            "    code{background:#edf2f7;padding:2px 6px;border-radius:4px;font-size:.85em;font-family:monospace}\n"
            "    .chart-wrap{position:relative;height:180px}\n"
            "    .filter-btn{border:none;color:#fff;padding:6px 12px;border-radius:20px;font-size:.85em;font-weight:600;cursor:pointer;margin-right:8px;opacity:0.6;transition:opacity 0.2s}\n"
            "    .filter-btn.active{opacity:1}\n"
            "    .search-box{width:100%;padding:10px 14px;border:1px solid #cbd5e0;border-radius:6px;font-size:1em;margin-bottom:16px}\n"
            "    .risk-gauge{text-align:center;font-size:3em;font-weight:800;line-height:1.2;margin-top:20px}\n"
            "    @media(max-width:800px){.grid3{grid-template-columns:1fr}}\n"
            "  </style>\n</head>\n<body>\n"
            "<div class='topbar'>\n  <div>\n"
            "    <h1>VulnScan - Vulnerability Assessment Report</h1>\n"
            f"    <div class='meta'>Target: <strong>{esc(self.target)}</strong> &nbsp;|&nbsp; Generated: {esc(self.generated_at)} &nbsp;|&nbsp; {timing_html}</div>\n"
            "  </div>\n</div>\n"
            "<div class='container'>\n"
            "  <div class='grid3'>\n"
            "    <div class='panel'><h2>Average Risk Score</h2><div class='risk-gauge' style='color:"+risk_color+"'>"+str(avg_risk)+"</div><div style='text-align:center;color:#718096;font-size:0.9em;margin-top:8px'>(0-100 Scale)</div></div>\n"
            "    <div class='panel'><h2>Severity Distribution</h2><div class='chart-wrap'><canvas id='pieChart'></canvas></div></div>\n"
            "    <div class='panel'><h2>Findings by Module</h2><div class='chart-wrap'><canvas id='barChart'></canvas></div></div>\n"
            "  </div>\n"
            "  <div class='panel' style='margin-bottom:20px;background:#f7fafc'>\n"
            "    <div style='display:flex;justify-content:space-between;align-items:center'>\n"
            "      <div><strong>Filter:</strong> <button class='filter-btn active' data-filter='ALL' style='background:#4a5568'>ALL</button>" + filter_buttons + "</div>\n"
            "      <input type='text' id='search' class='search-box' style='width:300px;margin:0' placeholder='Search findings...'>\n"
            "    </div>\n"
            "  </div>\n"
            "  <div class='panel'><h2>Findings ("+str(len(self.findings))+")</h2><div id='findingsList' style='margin-top:14px'>" + findings_html + "</div></div>\n"
            "</div>\n"
            "<script>\n"
            "(function() {\n"
            "  new Chart(document.getElementById('pieChart'), { type: 'doughnut', data: { labels: " + pie_labels + ", datasets: [{ data: " + pie_data + ", backgroundColor: " + pie_colors + ", borderWidth: 2 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { font: { size: 11 } } } } } });\n"
            "  new Chart(document.getElementById('barChart'), { type: 'bar', data: { labels: " + bar_labels + ", datasets: [{ label: 'Findings', data: " + bar_data + ", backgroundColor: " + bar_colors + ", borderRadius: 4 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 11 } } }, x: { ticks: { font: { size: 11 } } } } } });\n"
            "  \n"
            "  const searchInput = document.getElementById('search');\n"
            "  const filterBtns = document.querySelectorAll('.filter-btn');\n"
            "  const cards = document.querySelectorAll('.finding-card');\n"
            "  let currentFilter = 'ALL';\n"
            "  \n"
            "  function filterCards() {\n"
            "    const query = searchInput.value.toLowerCase();\n"
            "    cards.forEach(card => {\n"
            "      const text = card.textContent.toLowerCase();\n"
            "      const sev = card.getAttribute('data-severity');\n"
            "      const matchesSearch = text.includes(query);\n"
            "      const matchesFilter = currentFilter === 'ALL' || sev === currentFilter;\n"
            "      card.style.display = (matchesSearch && matchesFilter) ? 'block' : 'none';\n"
            "    });\n"
            "  }\n"
            "  \n"
            "  searchInput.addEventListener('input', filterCards);\n"
            "  \n"
            "  filterBtns.forEach(btn => {\n"
            "    btn.addEventListener('click', () => {\n"
            "      filterBtns.forEach(b => b.classList.remove('active'));\n"
            "      btn.classList.add('active');\n"
            "      currentFilter = btn.getAttribute('data-filter');\n"
            "      filterCards();\n"
            "    });\n"
            "  });\n"
            "})();\n"
            "</script>\n</body>\n</html>\n"
        )
        Path(path).write_text(html, encoding="utf-8")
