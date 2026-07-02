"""Unit tests for core/diff.py — baseline comparison engine."""
import json
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Finding, Severity
from core.diff import diff_findings, DiffResult, load_baseline


def _make_finding(title="Test", sev=Severity.MEDIUM, module="m", check_id="c-001"):
    return Finding(title=title, severity=sev, description="desc",
                   module=module, check_id=check_id)


def _write_report(findings, path):
    """Write a minimal report.json baseline file."""
    data = {
        "target": "localhost",
        "generated_at": "2024-01-01T00:00:00+00:00",
        "summary": {},
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


class TestDiffFindings:
    def test_all_new_when_baseline_empty(self, tmp_path):
        baseline_file = str(tmp_path / "report.json")
        _write_report([], baseline_file)

        current = [_make_finding("A"), _make_finding("B", check_id="c-002")]
        result = diff_findings(current, baseline_file)

        assert result is not None
        assert len(result.new) == 2
        assert len(result.resolved) == 0
        assert len(result.persisted) == 0

    def test_all_resolved_when_current_empty(self, tmp_path):
        baseline_file = str(tmp_path / "report.json")
        _write_report([_make_finding("A"), _make_finding("B", check_id="c-002")],
                      baseline_file)

        result = diff_findings([], baseline_file)

        assert result is not None
        assert len(result.new) == 0
        assert len(result.resolved) == 2
        assert len(result.persisted) == 0

    def test_persisted_when_same_findings(self, tmp_path):
        baseline_file = str(tmp_path / "report.json")
        findings = [_make_finding("A"), _make_finding("B", check_id="c-002")]
        _write_report(findings, baseline_file)

        result = diff_findings(findings, baseline_file)

        assert result is not None
        assert len(result.new) == 0
        assert len(result.resolved) == 0
        assert len(result.persisted) == 2

    def test_mixed_new_resolved_persisted(self, tmp_path):
        baseline_file = str(tmp_path / "report.json")
        old = [_make_finding("Old A"), _make_finding("Shared", check_id="shared-001")]
        _write_report(old, baseline_file)

        current = [_make_finding("New B", check_id="c-002"),
                   _make_finding("Shared", check_id="shared-001")]
        result = diff_findings(current, baseline_file)

        assert len(result.new) == 1
        assert result.new[0].title == "New B"
        assert len(result.resolved) == 1
        assert result.resolved[0].title == "Old A"
        assert len(result.persisted) == 1

    def test_returns_none_for_missing_baseline(self):
        result = diff_findings([], "/nonexistent/report.json")
        assert result is None

    def test_returns_none_for_malformed_json(self, tmp_path):
        bad_file = str(tmp_path / "bad.json")
        with open(bad_file, "w") as f:
            f.write("NOT JSON {{{")
        result = diff_findings([], bad_file)
        assert result is None

    def test_has_regressions_detects_new_critical(self, tmp_path):
        baseline_file = str(tmp_path / "report.json")
        _write_report([], baseline_file)

        current = [_make_finding("Critical!", sev=Severity.CRITICAL)]
        result = diff_findings(current, baseline_file)

        assert result is not None
        assert result.has_regressions is True

    def test_has_regressions_false_for_new_low(self, tmp_path):
        baseline_file = str(tmp_path / "report.json")
        _write_report([], baseline_file)

        current = [_make_finding("Low thing", sev=Severity.LOW)]
        result = diff_findings(current, baseline_file)

        assert result is not None
        assert result.has_regressions is False

    def test_new_findings_sorted_by_severity(self, tmp_path):
        baseline_file = str(tmp_path / "report.json")
        _write_report([], baseline_file)

        current = [
            _make_finding("Low", sev=Severity.LOW, check_id="c-001"),
            _make_finding("Critical", sev=Severity.CRITICAL, check_id="c-002"),
            _make_finding("Medium", sev=Severity.MEDIUM, check_id="c-003"),
        ]
        result = diff_findings(current, baseline_file)
        assert result.new[0].severity == Severity.CRITICAL
        assert result.new[-1].severity == Severity.LOW


class TestDiffResultOutputs:
    def test_to_json_produces_valid_json(self, tmp_path):
        baseline_file = str(tmp_path / "base.json")
        _write_report([], baseline_file)
        result = diff_findings([_make_finding("X")], baseline_file)

        out = str(tmp_path / "diff.json")
        result.to_json(out)

        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert "new" in data
        assert "resolved" in data
        assert "persisted" in data
        assert "summary" in data
        assert data["summary"]["new"] == 1

    def test_to_markdown_produces_file(self, tmp_path):
        baseline_file = str(tmp_path / "base.json")
        _write_report([], baseline_file)
        result = diff_findings([_make_finding("X")], baseline_file)

        out = str(tmp_path / "diff.md")
        result.to_markdown(out)

        content = open(out, encoding="utf-8").read()
        assert "# Scan Diff Report" in content
        assert "New Findings" in content

    def test_summary_counts(self, tmp_path):
        baseline_file = str(tmp_path / "base.json")
        _write_report([_make_finding("Old")], baseline_file)

        result = diff_findings([_make_finding("New", check_id="c-002")], baseline_file)
        s = result.summary()
        assert s["new"] == 1
        assert s["resolved"] == 1
        assert s["persisted"] == 0
