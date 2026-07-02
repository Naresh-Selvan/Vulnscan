"""Module 15: System Health, OS Errors & Crashes.

Checks:
  - Systemd failed services (systemctl --failed)
  - Scan kernel ring buffer (dmesg) for critical errors/crashes
  - Query system journal (journalctl) for recent high-priority error logs
"""
from __future__ import annotations
import subprocess
import os
from typing import List
from core.models import Checker, Finding, Severity

def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""

class SystemChecker(Checker):
    module_name = "system_health"

    def list_checks(self) -> List[str]:
        return [
            "Check for failed systemd services",
            "Scan kernel ring buffer (dmesg) for critical errors/crashes",
            "Query system journal (journalctl) for recent high-priority error logs",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_failed_services()
        findings += self._check_kernel_errors()
        findings += self._check_journal_errors()
        return findings

    def _check_failed_services(self) -> List[Finding]:
        findings = []
        out = _run(["systemctl", "list-units", "--state=failed", "--no-legend", "--no-pager"])
        failed_services = []
        for line in out.splitlines():
            line = line.strip()
            if line:
                failed_services.append(line)

        if failed_services:
            findings.append(Finding(
                title="Failed systemd services detected",
                severity=Severity.HIGH,
                description="One or more systemd services failed to start or crashed during execution. This indicates potential system misconfiguration, dependency issues, or crashed applications.",
                evidence="\n".join(failed_services[:10]),
                remediation="Investigate the service logs using `journalctl -u <service_name>` and restart it with `systemctl restart <service_name>`.",
                module=self.module_name,
                check_id="sys-001"
            ))
        return findings

    def _check_kernel_errors(self) -> List[Finding]:
        findings = []
        out = _run(["dmesg", "-l", "err,crit,alert,emerg"])
        if not out.strip():
            raw_dmesg = _run(["dmesg"])
            err_lines = []
            for line in raw_dmesg.splitlines():
                if any(x in line.lower() for x in ["error", "critical", "panic", "segfault", "oom-killer"]):
                    err_lines.append(line)
            out = "\n".join(err_lines[-20:])
            
        if out.strip():
            lines = out.strip().splitlines()
            findings.append(Finding(
                title="Critical kernel errors detected",
                severity=Severity.HIGH,
                description="The kernel ring buffer (dmesg) contains messages indicating hardware failures, driver issues, Out-Of-Memory (OOM) kills, or software segmentation faults.",
                evidence="\n".join(lines[-15:]),
                remediation="Inspect kernel logs, verify hardware status, check memory usage, or update the affected drivers.",
                module=self.module_name,
                check_id="sys-002"
            ))
        return findings

    def _check_journal_errors(self) -> List[Finding]:
        findings = []
        out = _run(["journalctl", "-p", "3", "-n", "20", "--no-pager"])
        if out.strip():
            lines = out.strip().splitlines()
            findings.append(Finding(
                title="Recent high-priority system journal errors",
                severity=Severity.MEDIUM,
                description="The system log daemon recorded recent errors or critical messages. This includes authorization failures, crashed system components, or bad configuration files.",
                evidence="\n".join(lines[-15:]),
                remediation="Run `sudo journalctl -p 3 -xb` to investigate the root causes of the logged errors.",
                module=self.module_name,
                check_id="sys-003"
            ))
        return findings
