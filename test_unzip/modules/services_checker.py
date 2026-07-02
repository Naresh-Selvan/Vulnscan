"""Module 14: Systemd Services & Daemons.

Checks:
  - World-writable systemd unit files (.service, .timer, etc.)
  - Executable paths in ExecStart= that are world-writable (Systemd Execution Hijacking)
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
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_writable_units()
        return findings

    def _check_writable_units(self) -> List[Finding]:
        findings = []
        
        # 1. Find all writable .service and .timer files in systemd directories
        search_dirs = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]
        writable_units = []
        
        for sdir in search_dirs:
            if not os.path.exists(sdir):
                continue
            out = _run(["find", sdir, "-type", "f", "-perm", "-0002", "-name", "*.service", "-o", "-name", "*.timer"])
            for ln in out.splitlines():
                if ln.strip():
                    writable_units.append(ln.strip())
                    
        if writable_units:
            findings.append(Finding(
                title="World-writable systemd unit files",
                severity=Severity.HIGH,
                description=(
                    "One or more systemd unit files are world-writable. An attacker can "
                    "modify these files to change the 'ExecStart' command, gaining arbitrary "
                    "code execution as root when the service restarts or the machine reboots."
                ),
                evidence="\n".join(writable_units[:20]),
                remediation="Remove world-writable permissions from systemd unit files (chmod o-w).",
                module=self.module_name,
                check_id="svc-001",
            ))
            
        # 2. Check for Execution Hijacking (writable ExecStart targets)
        hijackable_paths = []
        for sdir in search_dirs:
            if not os.path.exists(sdir):
                continue
                
            out = _run(["grep", "-Er", "^ExecStart=", sdir], timeout=120)
            for ln in out.splitlines():
                if ":" not in ln:
                    continue
                file_path, exec_line = ln.split(":", 1)
                
                # Extract the binary path (first token after ExecStart=, ignoring modifiers like - or @)
                exec_val = exec_line.replace("ExecStart=", "").strip()
                if exec_val.startswith("-") or exec_val.startswith("@") or exec_val.startswith("+") or exec_val.startswith("!"):
                    exec_val = exec_val[1:].strip()
                
                if not exec_val:
                    continue
                    
                bin_path = exec_val.split()[0]
                
                # Check if the binary exists and is world-writable
                if bin_path.startswith("/") and os.path.exists(bin_path):
                    try:
                        st = os.stat(bin_path)
                        # Check if world writable (0002)
                        if bool(st.st_mode & 0o0002):
                            hijackable_paths.append(f"{file_path} -> {bin_path} (Binary is world-writable)")
                    except OSError:
                        pass
                        
                    # Also check if the parent directory is world writable (allows replacing the binary)
                    parent_dir = os.path.dirname(bin_path)
                    if os.path.exists(parent_dir):
                        try:
                            dst = os.stat(parent_dir)
                            # Check if world writable AND NOT sticky bit (01000)
                            if bool(dst.st_mode & 0o0002) and not bool(dst.st_mode & 0o1000):
                                hijackable_paths.append(f"{file_path} -> {bin_path} (Parent dir '{parent_dir}' is world-writable)")
                        except OSError:
                            pass

        if hijackable_paths:
            findings.append(Finding(
                title="Systemd Execution Hijacking (Writable ExecStart paths)",
                severity=Severity.CRITICAL,
                description=(
                    "Systemd services were found that execute binaries located in world-writable "
                    "paths, or the binaries themselves are world-writable. A local attacker can "
                    "overwrite these binaries to achieve arbitrary root code execution when the service runs."
                ),
                evidence="\n".join(hijackable_paths[:20]),
                remediation=(
                    "Move service binaries to secure, root-owned directories (e.g. /usr/local/bin) "
                    "and ensure neither the binary nor its parent directory is world-writable."
                ),
                module=self.module_name,
                check_id="svc-002",
            ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] systemd units checked for hijacking.")
            
        return findings
