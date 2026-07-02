"""core/permissions.py — Privilege introspection and per-check degradation warnings.

Determines whether vulnscan is running with root/sudo privileges and provides
a per-module map of which checks will be silently degraded without them.
"""
from __future__ import annotations
import os
import shutil
from typing import Dict, List, NamedTuple


class CheckPrivilege(NamedTuple):
    check_name: str
    why_needed: str


# Map of module_key -> list of checks that are degraded without root
_PRIVILEGE_MAP: Dict[str, List[CheckPrivilege]] = {
    "auth": [
        CheckPrivilege("SUID/SGID scan (find)", "find across all mounts needs root to avoid permission errors"),
        CheckPrivilege("Shadow file check", "/etc/shadow is root-readable only"),
        CheckPrivilege("File capabilities (getcap)", "getcap -r / requires root for full traversal"),
        CheckPrivilege("PAM nullok detection", "/etc/pam.d/* files may be root-only readable"),
    ],
    "filesystem": [
        CheckPrivilege("World-writable file scan", "find across restricted directories needs root"),
        CheckPrivilege("Sensitive file permissions", "/etc/shadow, /etc/gshadow are root-readable"),
    ],
    "logging": [
        CheckPrivilege("Audit log permissions", "/var/log/audit/audit.log requires root"),
        CheckPrivilege("Audit rules (auditctl -l)", "auditctl requires root"),
    ],
    "kernel": [
        CheckPrivilege("Loaded kernel modules", "/proc/modules readable by root only on some kernels"),
    ],
    "packages": [
        CheckPrivilege("APT pending updates (apt-get --simulate)", "may require root for full index"),
    ],
    "cron": [
        CheckPrivilege("User crontab scan (/var/spool/cron/)", "/var/spool/cron is root-readable only"),
    ],
    "containers": [
        CheckPrivilege("Docker inspect (all containers)", "docker inspect requires docker group or root"),
    ],
    "crypto": [
        CheckPrivilege("Hardcoded credentials scan in /etc", "some /etc subdirs require root"),
    ],
}


def is_root() -> bool:
    """True if the current process is running as root (UID 0) or via sudo."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows — can't check meaningfully; assume not root
        return False


def has_sudo() -> bool:
    """True if sudo is available and SUDO_USER is set (i.e. we were invoked via sudo)."""
    return bool(os.environ.get("SUDO_USER")) and shutil.which("sudo") is not None


def degraded_checks(selected_modules: List[str]) -> Dict[str, List[CheckPrivilege]]:
    """Return the privilege map filtered to only the selected modules."""
    return {
        k: v for k, v in _PRIVILEGE_MAP.items()
        if k in selected_modules
    }


def print_privilege_warning(selected_modules: List[str]) -> None:
    """
    Print a formatted warning table listing all checks that will be
    silently degraded because the process is not running as root.
    Only called when is_root() is False.
    """
    import click
    degraded = degraded_checks(selected_modules)
    if not degraded:
        return

    click.echo(click.style(
        "\n  [!] Running without root privileges. "
        "The following checks will have REDUCED COVERAGE:\n",
        fg="yellow", bold=True,
    ))
    for module_key, checks in degraded.items():
        click.echo(click.style(f"    [{module_key}]", fg="yellow"))
        for c in checks:
            click.echo(f"      - {c.check_name}")
            click.echo(f"        Reason: {c.why_needed}")
    click.echo(
        click.style(
            "\n  For complete coverage: sudo python main.py\n",
            fg="yellow",
        )
    )
