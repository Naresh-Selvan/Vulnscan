"""Module: CPU Microarchitecture & Hardware Vulnerabilities."""
from __future__ import annotations
import os
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity

class CpuChecker(Checker):
    module_name = "cpu_microarchitecture"

    def list_checks(self) -> List[str]:
        return [
            "Check hardware vulnerabilities (Spectre, Meltdown, Retbleed, etc.)",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        
        findings: List[Finding] = []
        findings += self._check_cpu_vulnerabilities()
        return findings

    def _check_cpu_vulnerabilities(self) -> List[Finding]:
        vuln_dir = Path("/sys/devices/system/cpu/vulnerabilities")
        if not vuln_dir.exists() or not vuln_dir.is_dir():
            return []

        findings = []
        for p in vuln_dir.glob("*"):
            if not p.is_file():
                continue
                
            vuln_name = p.name
            try:
                status = p.read_text(encoding="utf-8").strip()
            except (PermissionError, OSError):
                continue
                
            # If the CPU is vulnerable, report it
            if status.startswith("Vulnerable"):
                findings.append(Finding(
                    title=f"Unmitigated CPU Vulnerability: {vuln_name}",
                    severity=Severity.HIGH,
                    description=f"The system's CPU is vulnerable to {vuln_name} and lacks microcode or OS mitigations.",
                    evidence=f"{vuln_dir}/{vuln_name}:\n{status}",
                    remediation="Apply the latest microcode updates from your vendor and ensure kernel mitigations are enabled (check kernel boot parameters).",
                    module=self.module_name,
                    check_id=f"cpu-{vuln_name}",
                    category="Hardware Security",
                    risk_score=75,
                    affected_asset=f"cpu-{vuln_name}",
                ))
                
        return findings
