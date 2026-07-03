"""Module 16: Memory & Swap Auditing.

Checks:
  - Swap configuration and adequacy
  - Memory overcommit settings
  - Critical processes with high OOM kill priority
  - Shared memory (/dev/shm) permissions and size
"""
from __future__ import annotations
import subprocess
import os
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity


def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError):
        return ""


class MemoryChecker(Checker):
    module_name = "memory"

    def list_checks(self) -> List[str]:
        return [
            "Validate swap partition/file exists and is adequate",
            "Check vm.overcommit_memory settings",
            "Flag critical processes with high OOM kill priority",
            "Audit /dev/shm permissions and mount options",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_swap_config()
        findings += self._check_memory_overcommit()
        findings += self._check_oom_score()
        findings += self._check_shared_memory()
        return findings

    def _check_swap_config(self) -> List[Finding]:
        findings = []
        meminfo = _read("/proc/meminfo")
        swap_total, mem_total = 0, 0
        for line in meminfo.splitlines():
            if line.startswith("SwapTotal:"):
                swap_total = int(line.split()[1])
            elif line.startswith("MemTotal:"):
                mem_total = int(line.split()[1])

        if mem_total > 0 and swap_total == 0:
            findings.append(Finding(
                title="No swap space configured",
                severity=Severity.MEDIUM,
                category="Performance",
                description=(
                    "The system has no swap partition or file. Without swap, "
                    "the OOM killer will be triggered earlier under memory pressure, "
                    "potentially killing critical services."
                ),
                evidence=f"MemTotal: {mem_total} kB, SwapTotal: 0 kB",
                remediation=(
                    "Create a swap file: "
                    "`fallocate -l 2G /swapfile && chmod 600 /swapfile && "
                    "mkswap /swapfile && swapon /swapfile`"
                ),
                module=self.module_name,
                check_id="mem-001",
            ))
        elif mem_total > 0 and swap_total < mem_total * 0.25:
            swap_mb = swap_total // 1024
            mem_mb = mem_total // 1024
            findings.append(Finding(
                title=f"Swap space is very small ({swap_mb} MB for {mem_mb} MB RAM)",
                severity=Severity.LOW,
                category="Performance",
                description=(
                    f"Swap ({swap_mb} MB) is less than 25% of physical RAM ({mem_mb} MB). "
                    "Consider increasing swap for better OOM resilience."
                ),
                evidence=f"MemTotal: {mem_total} kB, SwapTotal: {swap_total} kB",
                remediation="Increase swap size to at least 50% of RAM.",
                module=self.module_name,
                check_id="mem-002",
            ))
        return findings

    def _check_memory_overcommit(self) -> List[Finding]:
        findings = []
        val = _read("/proc/sys/vm/overcommit_memory").strip()
        if val == "1":
            findings.append(Finding(
                title="Memory overcommit is set to 'always' (dangerous)",
                severity=Severity.MEDIUM,
                category="Security",
                description=(
                    "vm.overcommit_memory=1 allows the kernel to always overcommit memory, "
                    "promising more RAM than is physically available. This can lead to "
                    "unpredictable OOM kills when the system runs out."
                ),
                evidence=f"/proc/sys/vm/overcommit_memory = {val}",
                remediation="Set to heuristic (0) or strict (2): `sysctl vm.overcommit_memory=2`.",
                module=self.module_name,
                check_id="mem-003",
            ))
        return findings

    def _check_oom_score(self) -> List[Finding]:
        findings = []
        critical_services = ["sshd", "systemd", "journald", "udevd", "dbus"]
        vulnerable = []

        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                comm = (pid_dir / "comm").read_text().strip()
                oom_adj = (pid_dir / "oom_score_adj").read_text().strip()
                oom_score = (pid_dir / "oom_score").read_text().strip()
            except (FileNotFoundError, PermissionError, OSError):
                continue

            for svc in critical_services:
                if svc in comm and int(oom_adj) >= 0 and int(oom_score) > 500:
                    vulnerable.append(
                        f"PID {pid_dir.name} ({comm}): oom_score={oom_score}, oom_score_adj={oom_adj}"
                    )
                    break

        if vulnerable:
            findings.append(Finding(
                title="Critical services vulnerable to OOM killer",
                severity=Severity.MEDIUM,
                category="System Health",
                description=(
                    "Critical system services have high OOM scores, making them targets "
                    "for the OOM killer under memory pressure. If these services are killed, "
                    "the system may become unresponsive or unmanageable."
                ),
                evidence="\n".join(vulnerable[:10]),
                remediation=(
                    "Protect critical services: "
                    "`echo -1000 > /proc/<pid>/oom_score_adj` or set OOMScoreAdjust=-1000 in the service unit."
                ),
                module=self.module_name,
                check_id="mem-004",
            ))
        return findings

    def _check_shared_memory(self) -> List[Finding]:
        findings = []
        mounts = _read("/proc/mounts")
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[1] == "/dev/shm":
                opts = parts[3]
                issues = []
                if "noexec" not in opts:
                    issues.append("noexec missing (allows code execution)")
                if "nosuid" not in opts:
                    issues.append("nosuid missing (allows SUID binaries)")

                if issues:
                    findings.append(Finding(
                        title="/dev/shm mounted with insecure options",
                        severity=Severity.MEDIUM,
                        category="Security",
                        description=(
                            f"The shared memory filesystem /dev/shm is missing security mount options: "
                            f"{', '.join(issues)}. Attackers frequently use /dev/shm to stage and "
                            "execute malicious payloads because it's a world-writable tmpfs."
                        ),
                        evidence=line.strip(),
                        remediation="Add noexec,nosuid,nodev to /dev/shm in /etc/fstab: `tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0`.",
                        module=self.module_name,
                        check_id="mem-005",
                        affected_asset="/dev/shm",
                    ))
                break
        return findings
