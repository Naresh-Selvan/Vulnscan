"""Module 14: Systemd Services & Daemons.

Checks:
  - World-writable systemd unit files (.service, .timer, etc.)
  - Executable paths in ExecStart= that are world-writable (Systemd Execution Hijacking)
  - Unmasked dangerous/debug services (emergency shells, debug shells)
  - Services in restart loops (crashlooping)
  - Enabled services pointing to deleted/missing binaries (orphan services)
  - System boot target validation
  - Misconfigured systemd timers
"""
from __future__ import annotations
import subprocess
import os
import re
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity


def _run(cmd: List[str], timeout: int = 60) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


class ServicesChecker(Checker):
    module_name = "systemd_services"

    def list_checks(self) -> List[str]:
        return [
            "Audit systemd unit files for world-writable permissions",
            "Parse systemd ExecStart paths for world-writable directories/binaries (Execution Hijacking)",
            "Detect unmasked dangerous services (emergency/debug shells)",
            "Detect services in restart loops (crashlooping)",
            "Find enabled services pointing to deleted/missing binaries",
            "Validate system boot target",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_writable_units()
        findings += self._check_dangerous_services()
        findings += self._check_crashlooping_services()
        findings += self._check_orphan_services()
        findings += self._check_default_target()
        return findings

    def _check_writable_units(self) -> List[Finding]:
        findings = []
        search_dirs = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]
        writable_units = []

        for sdir in search_dirs:
            if not os.path.exists(sdir):
                continue
            out = _run(["find", sdir, "-type", "f", "-perm", "-0002",
                        "-name", "*.service", "-o", "-name", "*.timer"])
            for ln in out.splitlines():
                if ln.strip():
                    writable_units.append(ln.strip())

        if writable_units:
            findings.append(Finding(
                title="World-writable systemd unit files",
                severity=Severity.HIGH,
                description=(
                    "One or more systemd unit files are world-writable. An attacker can "
                    "modify these to change the 'ExecStart' command, gaining arbitrary "
                    "code execution as root when the service restarts."
                ),
                evidence="\n".join(writable_units[:20]),
                remediation="Remove world-writable permissions: `chmod o-w <unit_file>`.",
                module=self.module_name,
                check_id="svc-001",
            ))

        # Check ExecStart hijacking
        hijackable_paths = []
        for sdir in search_dirs:
            if not os.path.exists(sdir):
                continue
            out = _run(["grep", "-Er", "^ExecStart=", sdir], timeout=120)
            for ln in out.splitlines():
                if ":" not in ln:
                    continue
                file_path, exec_line = ln.split(":", 1)
                exec_val = exec_line.replace("ExecStart=", "").strip()
                for prefix in "-@+!":
                    if exec_val.startswith(prefix):
                        exec_val = exec_val[1:].strip()
                if not exec_val:
                    continue
                bin_path = exec_val.split()[0]
                if bin_path.startswith("/") and os.path.exists(bin_path):
                    try:
                        st = os.stat(bin_path)
                        if bool(st.st_mode & 0o0002):
                            hijackable_paths.append(f"{file_path} -> {bin_path} (binary is world-writable)")
                    except OSError:
                        pass
                    parent_dir = os.path.dirname(bin_path)
                    if os.path.exists(parent_dir):
                        try:
                            dst = os.stat(parent_dir)
                            if bool(dst.st_mode & 0o0002) and not bool(dst.st_mode & 0o1000):
                                hijackable_paths.append(f"{file_path} -> {bin_path} (parent dir is world-writable)")
                        except OSError:
                            pass

        if hijackable_paths:
            findings.append(Finding(
                title="Systemd Execution Hijacking (Writable ExecStart paths)",
                severity=Severity.CRITICAL,
                description=(
                    "Systemd services execute binaries in world-writable paths. "
                    "A local attacker can overwrite these for arbitrary root code execution."
                ),
                evidence="\n".join(hijackable_paths[:20]),
                remediation="Move binaries to secure root-owned directories and fix permissions.",
                module=self.module_name,
                check_id="svc-002",
            ))
        return findings

    def _check_dangerous_services(self) -> List[Finding]:
        findings = []
        dangerous = {
            "debug-shell.service": "Root shell on tty9 without authentication",
            "emergency.service": "Emergency mode drops to root shell",
            "rescue.service": "Rescue mode can bypass normal authentication",
        }
        out = _run(["systemctl", "list-unit-files", "--no-legend", "--no-pager"])
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            unit, state = parts[0], parts[1]
            if unit in dangerous and state in ("enabled", "static"):
                if unit == "debug-shell.service" and state == "enabled":
                    findings.append(Finding(
                        title=f"Dangerous service active: {unit}",
                        severity=Severity.CRITICAL,
                        category="Security",
                        risk_score=95,
                        description=(
                            f"{unit} is enabled. {dangerous[unit]}. "
                            "This provides unauthenticated root access and should NEVER be enabled in production."
                        ),
                        evidence=f"{unit}: {state}",
                        remediation=f"Disable immediately: `systemctl disable --now {unit}` and `systemctl mask {unit}`.",
                        module=self.module_name,
                        check_id="svc-003",
                        affected_asset=unit,
                    ))
        return findings

    def _check_crashlooping_services(self) -> List[Finding]:
        findings = []
        out = _run(["systemctl", "list-units", "--state=failed", "--no-legend", "--no-pager"])
        failed = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            unit = line.split()[0]
            # Check if the service has been restarting frequently
            status = _run(["systemctl", "show", unit, "--property=NRestarts", "--no-pager"])
            restarts = 0
            for l in status.splitlines():
                if l.startswith("NRestarts="):
                    try:
                        restarts = int(l.split("=")[1])
                    except ValueError:
                        pass
            if restarts >= 3:
                failed.append(f"{unit}: {restarts} restarts")

        if failed:
            findings.append(Finding(
                title="Services in restart loops (crashlooping)",
                severity=Severity.HIGH,
                category="System Health",
                description=(
                    "Services have restarted 3 or more times, indicating persistent crashes. "
                    "Crashlooping services waste CPU, fill logs, and may leave the system in a degraded state."
                ),
                evidence="\n".join(failed[:10]),
                remediation="Check logs with `journalctl -u <service>` and fix the underlying issue.",
                module=self.module_name,
                check_id="svc-004",
            ))
        return findings

    def _check_orphan_services(self) -> List[Finding]:
        findings = []
        out = _run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"])
        orphans = []
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            unit = parts[0]
            # Get the ExecStart path
            exec_out = _run(["systemctl", "show", unit, "--property=ExecStart", "--no-pager"])
            for l in exec_out.splitlines():
                if "path=" in l:
                    match = re.search(r'path=(\S+)', l)
                    if match:
                        binary = match.group(1).rstrip(";")
                        if binary.startswith("/") and not os.path.exists(binary):
                            orphans.append(f"{unit} -> {binary} (MISSING)")
                            break

        if orphans:
            findings.append(Finding(
                title="Enabled services with missing binaries",
                severity=Severity.MEDIUM,
                category="System Health",
                description=(
                    "Enabled services reference binaries that no longer exist on disk. "
                    "These services will fail on restart and may indicate incomplete package removal."
                ),
                evidence="\n".join(orphans[:10]),
                remediation="Disable orphaned services: `systemctl disable <service>`.",
                module=self.module_name,
                check_id="svc-005",
            ))
        return findings

    def _check_default_target(self) -> List[Finding]:
        findings = []
        out = _run(["systemctl", "get-default"]).strip()
        if out in ("rescue.target", "emergency.target"):
            findings.append(Finding(
                title=f"System default boot target is {out}",
                severity=Severity.HIGH,
                category="System Health",
                description=(
                    f"The default systemd boot target is set to '{out}'. "
                    "This means the system will boot into a minimal recovery mode instead of "
                    "the normal multi-user environment. Services will not start automatically."
                ),
                evidence=f"Default target: {out}",
                remediation="Set to multi-user: `systemctl set-default multi-user.target` or graphical: `systemctl set-default graphical.target`.",
                module=self.module_name,
                check_id="svc-006",
                affected_asset=out,
            ))
        return findings
