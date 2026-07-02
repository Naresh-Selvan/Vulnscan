"""Unit tests for core/report.py — JSON, Markdown, HTML generation."""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Finding, Severity
from core.report import Report


def _findings_set():
    return [
        Finding(title="Crit finding", severity=Severity.CRITICAL,
                description="Very bad", evidence="proof", remediation="fix it",
                cve_refs=["CVE-2024-0001"], cis_refs=["CIS 1.1"],
                module="test_mod", check_id="t-001"),
        Finding(title="Info finding", severity=Severity.INFO,
                description="FYI", module="test_mod", check_id="t-002"),
        Finding(title="High finding", severity=Severity.HIGH,
                description="Bad", module="other_mod", check_id="o-001"),
    ]


class TestReport:
    def test_findings_sorted_by_severity_descending(self):
        findings = _findings_set()
        r = Report(findings)
        sevs = [f.severity for f in r.findings]
        assert sevs[0] == Severity.CRITICAL
        assert sevs[-1] == Severity.INFO

    def test_summary_counts_correct(self):
        findings = _findings_set()
        r = Report(findings)
        counts = r.summary_counts()
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 1
        assert counts["INFO"] == 1
        assert counts["MEDIUM"] == 0
        assert counts["LOW"] == 0

    def test_summary_all_severity_keys_present(self):
        r = Report([])
        counts = r.summary_counts()
        assert set(counts.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class TestJsonReport:
    def test_produces_valid_json(self, tmp_path):
        r = Report(_findings_set(), target="testhost")
        out = str(tmp_path / "report.json")
        r.to_json(out)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert data["target"] == "testhost"
        assert len(data["findings"]) == 3
        assert "generated_at" in data
        assert "summary" in data

    def test_findings_sorted_in_json(self, tmp_path):
        r = Report(_findings_set())
        out = str(tmp_path / "report.json")
        r.to_json(out)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        severities = [f["severity"] for f in data["findings"]]
        assert severities[0] == "CRITICAL"
        assert severities[-1] == "INFO"

    def test_empty_findings_produces_valid_json(self, tmp_path):
        r = Report([], target="empty")
        out = str(tmp_path / "report.json")
        r.to_json(out)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert data["findings"] == []

    def test_all_finding_fields_in_json(self, tmp_path):
        r = Report(_findings_set())
        out = str(tmp_path / "report.json")
        r.to_json(out)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        first = data["findings"][0]
        assert first["cve_refs"] == ["CVE-2024-0001"]
        assert first["cis_refs"] == ["CIS 1.1"]
        assert first["evidence"] == "proof"
        assert first["remediation"] == "fix it"


class TestMarkdownReport:
    def test_produces_file_with_content(self, tmp_path):
        r = Report(_findings_set())
        out = str(tmp_path / "report.md")
        r.to_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "# Vulnerability Assessment Report" in content

    def test_contains_all_findings(self, tmp_path):
        r = Report(_findings_set())
        out = str(tmp_path / "report.md")
        r.to_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "Crit finding" in content
        assert "Info finding" in content
        assert "High finding" in content

    def test_contains_summary_table(self, tmp_path):
        r = Report(_findings_set())
        out = str(tmp_path / "report.md")
        r.to_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "| Severity" in content
        assert "CRITICAL" in content

    def test_empty_findings_graceful(self, tmp_path):
        r = Report([])
        out = str(tmp_path / "report.md")
        r.to_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "No findings recorded" in content


class TestHtmlReport:
    def test_produces_valid_html_structure(self, tmp_path):
        r = Report(_findings_set(), target="myhost")
        out = str(tmp_path / "report.html")
        r.to_html(out)
        content = open(out, encoding="utf-8").read()
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content

    def test_contains_target_in_title(self, tmp_path):
        r = Report([], target="scanme.local")
        out = str(tmp_path / "report.html")
        r.to_html(out)
        content = open(out, encoding="utf-8").read()
        assert "scanme.local" in content

    def test_contains_chartjs_script(self, tmp_path):
        r = Report(_findings_set())
        out = str(tmp_path / "report.html")
        r.to_html(out)
        content = open(out, encoding="utf-8").read()
        assert "chart.js" in content.lower() or "Chart" in content

    def test_xss_escaping(self, tmp_path):
        """HTML-special chars in finding content must be escaped."""
        f = Finding(
            title='<script>alert("xss")</script>',
            severity=Severity.HIGH,
            description="<b>bold</b> & stuff",
            module="m", check_id="x-001",
        )
        r = Report([f])
        out = str(tmp_path / "report.html")
        r.to_html(out)
        content = open(out, encoding="utf-8").read()
        # Raw script tag must NOT appear unescaped
        assert "<script>alert" not in content
        # Escaped version must appear
        assert "&lt;script&gt;" in content

    def test_empty_findings_graceful(self, tmp_path):
        r = Report([])
        out = str(tmp_path / "report.html")
        r.to_html(out)
        content = open(out, encoding="utf-8").read()
        assert "No findings recorded" in content
