"""Unit tests for core/models.py — Finding, Severity, Checker."""
import pytest
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Finding, Severity, Checker
from typing import List


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL.value > Severity.HIGH.value
        assert Severity.HIGH.value > Severity.MEDIUM.value
        assert Severity.MEDIUM.value > Severity.LOW.value
        assert Severity.LOW.value > Severity.INFO.value

    def test_str_representation(self):
        assert str(Severity.CRITICAL) == "CRITICAL"
        assert str(Severity.INFO) == "INFO"

    def test_all_members_present(self):
        names = {s.name for s in Severity}
        assert names == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_sort_by_value(self):
        sevs = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH]
        sorted_sevs = sorted(sevs, key=lambda s: s.value, reverse=True)
        assert sorted_sevs[0] == Severity.CRITICAL
        assert sorted_sevs[-1] == Severity.INFO


class TestFinding:
    def test_minimal_construction(self):
        f = Finding(
            title="Test finding",
            severity=Severity.HIGH,
            description="Something bad happened",
        )
        assert f.title == "Test finding"
        assert f.severity == Severity.HIGH
        assert f.description == "Something bad happened"
        assert f.evidence == ""
        assert f.remediation == ""
        assert f.cve_refs == []
        assert f.cis_refs == []
        assert f.module == ""
        assert f.check_id == ""
        assert f.timestamp != ""  # auto-populated

    def test_full_construction(self):
        f = Finding(
            title="Full finding",
            severity=Severity.CRITICAL,
            description="desc",
            evidence="evidence here",
            remediation="fix it",
            cve_refs=["CVE-2023-1234"],
            cis_refs=["CIS Linux 1.1"],
            module="test_module",
            check_id="test-001",
        )
        assert f.cve_refs == ["CVE-2023-1234"]
        assert f.check_id == "test-001"

    def test_to_dict_keys(self):
        f = Finding(title="X", severity=Severity.LOW, description="Y")
        d = f.to_dict()
        expected_keys = {
            "title", "severity", "description", "evidence", "remediation",
            "cve_refs", "cis_refs", "module", "check_id", "timestamp",
            "risk_score", "category", "affected_asset",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_severity_is_string(self):
        f = Finding(title="X", severity=Severity.MEDIUM, description="Y")
        d = f.to_dict()
        assert d["severity"] == "MEDIUM"

    def test_to_dict_roundtrip_severity(self):
        f = Finding(title="X", severity=Severity.CRITICAL, description="Y")
        d = f.to_dict()
        assert Severity[d["severity"]] == Severity.CRITICAL

    def test_default_lists_are_not_shared(self):
        """Mutable defaults must not be shared between instances."""
        f1 = Finding(title="A", severity=Severity.INFO, description="A")
        f2 = Finding(title="B", severity=Severity.INFO, description="B")
        f1.cve_refs.append("CVE-1")
        assert f2.cve_refs == []

    def test_timestamp_is_utc_format(self):
        import datetime
        f = Finding(title="X", severity=Severity.INFO, description="Y")
        # Should be parseable as ISO-8601 with timezone info
        dt = datetime.datetime.fromisoformat(f.timestamp)
        assert dt.tzinfo is not None


class TestCheckerInterface:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            Checker()  # abstract class

    def test_concrete_subclass(self):
        class ConcreteChecker(Checker):
            module_name = "test"

            def list_checks(self) -> List[str]:
                return ["check A", "check B"]

            def run(self) -> List[Finding]:
                return [Finding(title="found", severity=Severity.LOW, description="x")]

        c = ConcreteChecker(dry_run=False, logger=None)
        assert c.dry_run is False
        assert c.logger is None
        checks = c.list_checks()
        assert len(checks) == 2
        findings = c.run()
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_dry_run_attribute(self):
        class SimpleChecker(Checker):
            module_name = "simple"

            def list_checks(self):
                return []

            def run(self):
                return []

        c = SimpleChecker(dry_run=True)
        assert c.dry_run is True
