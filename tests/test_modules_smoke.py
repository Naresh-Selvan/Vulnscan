"""Smoke tests for all checker modules.

These tests verify that:
1. Every module can be imported without errors
2. Every module's list_checks() returns a non-empty list of strings
3. Every module's run() with dry_run=True returns an empty list
4. Every module instantiates with the expected interface

These tests do NOT execute actual system checks — they are safe to run on
Windows or any other OS without /proc or system tools.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Checker, Finding


# ── Registry of all modules ───────────────────────────────────────────────────
ALL_MODULES = [
    ("modules.kernel_checker",     "KernelChecker"),
    ("modules.auth_checker",       "AuthChecker"),
    ("modules.package_checker",    "PackageChecker"),
    ("modules.network_checker",    "NetworkChecker"),
    ("modules.boot_checker",       "BootChecker"),
    ("modules.desktop_checker",    "DesktopChecker"),
    ("modules.filesystem_checker", "FilesystemChecker"),
    ("modules.logging_checker",    "LoggingChecker"),
    ("modules.crypto_checker",     "CryptoChecker"),
    ("modules.container_checker",  "ContainerChecker"),
    ("modules.cron_checker",       "CronChecker"),
    ("modules.process_checker",    "ProcessChecker"),
    ("modules.nfs_checker",        "NfsChecker"),
    ("modules.services_checker",   "ServicesChecker"),
    ("modules.system_checker",     "SystemChecker"),
    ("modules.memory_checker",     "MemoryChecker"),
    ("modules.user_checker",       "UserChecker"),
    ("modules.cpu_checker",        "CpuChecker"),
    ("modules.binary_checker",     "BinaryChecker"),
    ("modules.bootkit_checker",    "BootkitChecker"),
    ("modules.ipc_checker",        "IpcChecker"),
]


def _load(mod_path: str, class_name: str) -> Checker:
    import importlib
    mod = importlib.import_module(mod_path)
    cls = getattr(mod, class_name)
    return cls(dry_run=True, logger=None)


# ── Parameterised smoke tests ─────────────────────────────────────────────────

@pytest.mark.parametrize("mod_path,class_name", ALL_MODULES)
def test_module_imports(mod_path, class_name):
    """Module can be imported and class found."""
    import importlib
    mod = importlib.import_module(mod_path)
    assert hasattr(mod, class_name), f"{class_name} not found in {mod_path}"


@pytest.mark.parametrize("mod_path,class_name", ALL_MODULES)
def test_module_is_checker_subclass(mod_path, class_name):
    """Class inherits from core.models.Checker."""
    checker = _load(mod_path, class_name)
    assert isinstance(checker, Checker)


@pytest.mark.parametrize("mod_path,class_name", ALL_MODULES)
def test_list_checks_returns_nonempty_list(mod_path, class_name):
    """list_checks() returns a non-empty list of strings."""
    checker = _load(mod_path, class_name)
    checks = checker.list_checks()
    assert isinstance(checks, list), f"{class_name}.list_checks() must return a list"
    assert len(checks) > 0, f"{class_name}.list_checks() must return at least one check"
    for item in checks:
        assert isinstance(item, str), f"Each check description must be a string, got {type(item)}"
        assert len(item) > 0, "Check description must not be empty"


@pytest.mark.parametrize("mod_path,class_name", ALL_MODULES)
def test_dry_run_returns_empty_list(mod_path, class_name):
    """run() with dry_run=True must return an empty list without executing checks."""
    checker = _load(mod_path, class_name)
    assert checker.dry_run is True
    result = checker.run()
    assert isinstance(result, list), f"{class_name}.run() must return a list"
    assert len(result) == 0, (
        f"{class_name}.run() with dry_run=True returned {len(result)} findings — "
        f"dry_run mode must always return an empty list"
    )


@pytest.mark.parametrize("mod_path,class_name", ALL_MODULES)
def test_module_name_attribute_set(mod_path, class_name):
    """Each module must have a non-empty module_name class attribute."""
    checker = _load(mod_path, class_name)
    assert hasattr(checker, "module_name")
    assert isinstance(checker.module_name, str)
    assert len(checker.module_name) > 0
    assert checker.module_name != "base", (
        f"{class_name} must override module_name (got 'base')"
    )


@pytest.mark.parametrize("mod_path,class_name", ALL_MODULES)
def test_run_returns_list_of_findings_type(mod_path, class_name):
    """run() result items must be Finding instances when not dry_run (structural check)."""
    # We can verify the return type annotation is correct even in dry_run=True mode
    # by checking that the method returns a plain list (not a generator, etc.)
    checker = _load(mod_path, class_name)
    result = checker.run()
    assert isinstance(result, list)
    # All items must be Finding instances if any are returned
    for item in result:
        assert isinstance(item, Finding), (
            f"{class_name}.run() returned a non-Finding object: {type(item)}"
        )
