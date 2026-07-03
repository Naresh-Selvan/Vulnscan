"""Module: Inter-Process Communication (IPC) & D-Bus."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity

class IpcChecker(Checker):
    module_name = "ipc_dbus"

    def list_checks(self) -> List[str]:
        return [
            "Check for custom or overly permissive Polkit rules",
            "Scan for world-readable shared memory segments (ipcs)",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        
        findings: List[Finding] = []
        findings += self._check_polkit_rules()
        findings += self._check_shared_memory()
        return findings

    def _check_polkit_rules(self) -> List[Finding]:
        polkit_dir = Path("/etc/polkit-1/rules.d")
        if not polkit_dir.exists():
            return []

        findings = []
        try:
            for rule_file in polkit_dir.glob("*.rules"):
                if not rule_file.is_file():
                    continue
                
                content = rule_file.read_text(encoding="utf-8")
                # Very basic check for permissive return values without auth
                if "return polkit.Result.YES" in content and "subject.isInGroup" not in content and "subject.user" not in content:
                    findings.append(Finding(
                        title=f"Permissive Polkit Rule: {rule_file.name}",
                        severity=Severity.HIGH,
                        description="Found a Polkit rule that unconditionally returns 'YES', which may allow unprivileged users to bypass authorization for administrative actions.",
                        evidence=f"File: {rule_file}\nContent snippet:\n{content[:200]}",
                        remediation="Review the Polkit rule and ensure it requires appropriate authorization (e.g., polkit.Result.AUTH_ADMIN).",
                        module=self.module_name,
                        check_id=f"ipc-polkit-{rule_file.name}",
                        category="Access Control",
                        risk_score=80,
                        affected_asset=str(rule_file),
                    ))
        except (PermissionError, OSError) as e:
            if self.logger:
                self.logger.warning(f"Could not read polkit rules: {e}")

        return findings

    def _check_shared_memory(self) -> List[Finding]:
        try:
            out = subprocess.run(["ipcs", "-m"], capture_output=True, text=True, timeout=5).stdout
            world_readable = []
            
            # Typical ipcs -m output:
            # key        shmid      owner      perms      bytes      nattch     status      
            # 0x00000000 32768      root       644        80         2                       
            lines = out.strip().splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 4 and parts[0].startswith("0x"):
                    perms = parts[3]
                    # Check if permissions end with 4, 5, 6, or 7 (world readable/writable)
                    if perms.isdigit() and len(perms) >= 3:
                        if perms[-1] in ('4', '5', '6', '7'):
                            owner = parts[2]
                            world_readable.append(f"shmid {parts[1]} (owner: {owner}, perms: {perms}, bytes: {parts[4]})")
            
            if world_readable:
                return [Finding(
                    title="World-readable Shared Memory Segments (SHM)",
                    severity=Severity.MEDIUM,
                    description=f"Found {len(world_readable)} shared memory segments that are world-readable. This could allow unprivileged users to dump sensitive memory data from other applications (e.g., X11 or databases).",
                    evidence="\n".join(world_readable),
                    remediation="Configure applications to use strict IPC permissions (e.g., 600).",
                    module=self.module_name,
                    check_id="ipc-shm",
                    category="Memory Security",
                    risk_score=50,
                    affected_asset="shm",
                )]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return []
