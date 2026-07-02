"""Unit tests for core/scope.py — Allowlist enforcement."""
import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scope import Allowlist, ScopeError


def _write_allowlist(content: str) -> str:
    """Write YAML to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class TestAllowlistLocalOnly:
    def test_localhost_allowed_by_default(self):
        path = _write_allowlist("local_only: true\ntargets: []\n")
        scope = Allowlist(path)
        # Should not raise
        scope.assert_allowed("localhost")
        scope.assert_allowed("127.0.0.1")

    def test_loopback_range_allowed(self):
        path = _write_allowlist("local_only: true\n")
        scope = Allowlist(path)
        scope.assert_allowed("127.0.0.2")
        scope.assert_allowed("127.255.255.254")

    def test_external_ip_blocked_when_local_only(self):
        path = _write_allowlist("local_only: true\ntargets: []\n")
        scope = Allowlist(path)
        with pytest.raises(ScopeError):
            scope.assert_allowed("10.0.0.1")

    def test_hostname_localhost_variants(self):
        path = _write_allowlist("local_only: true\n")
        scope = Allowlist(path)
        scope.assert_allowed("localhost")
        scope.assert_allowed("LOCALHOST")

    def test_external_hostname_blocked_when_local_only(self):
        path = _write_allowlist("local_only: true\n")
        scope = Allowlist(path)
        with pytest.raises(ScopeError):
            scope.assert_allowed("example.com")


class TestAllowlistExplicitTargets:
    def test_explicit_target_allowed(self):
        path = _write_allowlist("local_only: false\ntargets:\n  - 10.0.0.5\n")
        scope = Allowlist(path)
        scope.assert_allowed("10.0.0.5")

    def test_unlisted_target_blocked(self):
        path = _write_allowlist("local_only: false\ntargets:\n  - 10.0.0.5\n")
        scope = Allowlist(path)
        with pytest.raises(ScopeError):
            scope.assert_allowed("10.0.0.6")

    def test_multiple_targets(self):
        path = _write_allowlist(
            "local_only: false\ntargets:\n  - 10.0.0.5\n  - 192.168.1.10\n"
        )
        scope = Allowlist(path)
        scope.assert_allowed("10.0.0.5")
        scope.assert_allowed("192.168.1.10")
        with pytest.raises(ScopeError):
            scope.assert_allowed("10.0.0.99")


class TestAllowlistFileErrors:
    def test_missing_file_raises(self):
        with pytest.raises((FileNotFoundError, ScopeError)):
            Allowlist("/nonexistent/path/allowlist.yaml")

    def test_empty_file_defaults_to_local_only(self):
        path = _write_allowlist("")
        scope = Allowlist(path)
        scope.assert_allowed("localhost")
        with pytest.raises(ScopeError):
            scope.assert_allowed("8.8.8.8")


class TestScopeError:
    def test_scope_error_message_contains_target(self):
        path = _write_allowlist("local_only: true\n")
        scope = Allowlist(path)
        try:
            scope.assert_allowed("evil.com")
        except ScopeError as e:
            assert "evil.com" in str(e)
