"""Module 15: System Health, OS Errors & Crashes.

Checks:
  - Systemd failed services (systemctl --failed)
  - Scan kernel ring buffer (dmesg) for critical errors/crashes
  - Query system journal (journalctl) for recent high-priority error logs
  - Disk usage critical thresholds
  - Zombie/defunct processes
  - Out-Of-Memory (OOM) kill events
  - Unexpected reboot history
  - Core dump detection
  - Swap usage monitoring
  - CPU load average monitoring
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


class SystemChecker(Checker):
    module_name = "system_health"

    def list_checks(self) -> List[str]:
        return [
            "Check for failed systemd services",
            "Scan kernel ring buffer (dmesg) for critical errors/crashes",
            "Query system journal (journalctl) for recent high-priority error logs",
            "Check disk usage for critically full partitions",
            "Detect zombie/defunct processes",
            "Scan for Out-Of-Memory (OOM) kill events",
            "Inspect reboot history for unexpected restarts",
            "Detect application core dump files",
            "Check swap space usage",
            "Monitor CPU load average",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_failed_services()
        findings += self._check_kernel_errors()
        findings += self._check_journal_errors()
        findings += self._check_disk_usage()
        findings += self._check_zombie_processes()
        findings += self._check_oom_kills()
        findings += self._check_reboot_history()
        findings += self._check_coredumps()
        findings += self._check_swap_usage()
        findings += self._check_load_average()
        return findings

    # ── Existing checks (improved) ────────────────────────────────────────────

    def _check_failed_services(self) -> List[Finding]:
        findings = []
        out = _run(["systemctl", "list-units", "--state=failed", "--no-legend", "--no-pager"])
        failed = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if failed:
            findings.append(Finding(
                title="Failed systemd services detected",
                severity=Severity.HIGH,
                category="System Health",
                description=(
                    "One or more systemd services failed to start or crashed. "
                    "This indicates system misconfiguration, dependency issues, or crashed applications."
                ),
                evidence="\n".join(failed[:15]),
                remediation="Investigate with `journalctl -u <service>` and restart with `systemctl restart <service>`.",
                module=self.module_name,
                check_id="sys-001",
                affected_asset=failed[0].split()[0] if failed else "",
            ))
        return findings

    def _check_kernel_errors(self) -> List[Finding]:
        findings = []
        out = _run(["dmesg", "-l", "err,crit,alert,emerg"])
        if not out.strip():
            raw = _run(["dmesg"])
            err_lines = [l for l in raw.splitlines()
                         if any(k in l.lower() for k in ["error", "critical", "panic", "segfault", "oom-killer"])]
            out = "\n".join(err_lines[-20:])

        if out.strip():
            lines = out.strip().splitlines()
            findings.append(Finding(
                title="Critical kernel errors detected",
                severity=Severity.HIGH,
                category="System Health",
                description=(
                    "The kernel ring buffer (dmesg) contains messages indicating "
                    "hardware failures, driver issues, OOM kills, or segmentation faults."
                ),
                evidence="\n".join(lines[-15:]),
                remediation="Inspect kernel logs, verify hardware, check memory, or update affected drivers.",
                module=self.module_name,
                check_id="sys-002",
            ))
        return findings

    def _check_journal_errors(self) -> List[Finding]:
        findings = []
        out = _run(["journalctl", "-p", "3", "-n", "25", "--no-pager"])
        if out.strip():
            lines = out.strip().splitlines()
            findings.append(Finding(
                title="Recent high-priority system journal errors",
                severity=Severity.MEDIUM,
                category="System Health",
                description=(
                    "The system log daemon recorded recent errors or critical messages. "
                    "This includes authorization failures, crashed components, or bad configs."
                ),
                evidence="\n".join(lines[-15:]),
                remediation="Run `sudo journalctl -p 3 -xb` to investigate root causes.",
                module=self.module_name,
                check_id="sys-003",
            ))
        return findings

    # ── New deep checks ───────────────────────────────────────────────────────

    def _check_disk_usage(self) -> List[Finding]:
        findings = []
        out = _run(["df", "-h", "--output=pcent,target", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs"])
        critical, warning = [], []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                pct = int(parts[0].replace("%", ""))
            except ValueError:
                continue
            mount = parts[1]
            if pct >= 95:
                critical.append(f"{mount}: {pct}% full")
            elif pct >= 85:
                warning.append(f"{mount}: {pct}% full")

        if critical:
            findings.append(Finding(
                title="Disk partitions critically full (≥95%)",
                severity=Severity.CRITICAL,
                category="System Health",
                risk_score=98,
                description=(
                    "One or more disk partitions are at or above 95% capacity. "
                    "If they reach 100%, the system will crash, logs will stop writing, "
                    "and services will fail to start."
                ),
                evidence="\n".join(critical),
                remediation="Free up space immediately. Check large files with `du -ah / | sort -rh | head -20`.",
                module=self.module_name,
                check_id="sys-004",
                affected_asset=critical[0].split(":")[0],
            ))
        if warning:
            findings.append(Finding(
                title="Disk partitions nearing capacity (≥85%)",
                severity=Severity.MEDIUM,
                category="System Health",
                description="One or more partitions are above 85% capacity.",
                evidence="\n".join(warning),
                remediation="Monitor disk usage and plan cleanup or expansion.",
                module=self.module_name,
                check_id="sys-005",
            ))
        return findings

    def _check_zombie_processes(self) -> List[Finding]:
        findings = []
        out = _run(["ps", "aux"])
        zombies = [l for l in out.splitlines() if " Z " in l or " Z+ " in l]
        if zombies:
            findings.append(Finding(
                title="Zombie (defunct) processes detected",
                severity=Severity.MEDIUM,
                category="System Health",
                description=(
                    "Zombie processes are dead processes whose parent hasn't collected "
                    "their exit status. Large numbers indicate a buggy parent process or resource leak."
                ),
                evidence="\n".join(zombies[:10]),
                remediation="Identify the parent process (PPID) and restart it, or reboot the system.",
                module=self.module_name,
                check_id="sys-006",
            ))
        return findings

    def _check_oom_kills(self) -> List[Finding]:
        findings = []
        out = _run(["dmesg"])
        oom_lines = [l for l in out.splitlines() if "oom-killer" in l.lower() or "out of memory" in l.lower()]
        if oom_lines:
            findings.append(Finding(
                title="Out-Of-Memory (OOM) kill events detected",
                severity=Severity.HIGH,
                category="System Health",
                risk_score=85,
                description=(
                    "The Linux kernel OOM killer was invoked, forcefully terminating processes "
                    "to free memory. This indicates the system ran out of RAM and swap. "
                    "Critical services may have been killed."
                ),
                evidence="\n".join(oom_lines[-10:]),
                remediation="Add more RAM, increase swap, or investigate memory-hungry processes.",
                module=self.module_name,
                check_id="sys-007",
            ))
        return findings

    def _check_reboot_history(self) -> List[Finding]:
        findings = []
        out = _run(["last", "reboot", "-n", "10", "--time-format", "iso"])
        if not out.strip():
            out = _run(["last", "reboot", "-n", "10"])
        reboots = [l for l in out.splitlines() if l.strip() and "reboot" in l.lower()]
        if len(reboots) >= 5:
            findings.append(Finding(
                title="Frequent system reboots detected",
                severity=Severity.MEDIUM,
                category="System Health",
                description=(
                    f"The system has rebooted {len(reboots)} times recently. "
                    "Frequent reboots may indicate kernel panics, hardware issues, or power problems."
                ),
                evidence="\n".join(reboots[:10]),
                remediation="Check for kernel panics in `journalctl -b -1 -p 0` and hardware issues in `dmesg`.",
                module=self.module_name,
                check_id="sys-008",
            ))
        return findings

    def _check_coredumps(self) -> List[Finding]:
        findings = []
        # Check systemd coredump storage
        out = _run(["coredumpctl", "list", "--no-pager", "-n", "10"])
        if out.strip() and "No coredumps" not in out:
            lines = [l for l in out.splitlines() if l.strip()]
            if len(lines) > 1:  # header + at least one entry
                findings.append(Finding(
                    title="Application core dumps detected",
                    severity=Severity.MEDIUM,
                    category="System Health",
                    description=(
                        "One or more applications have crashed and generated core dump files. "
                        "Core dumps may contain sensitive data (passwords, keys) in memory."
                    ),
                    evidence="\n".join(lines[-10:]),
                    remediation="Investigate crashes. Disable core dumps if not needed: add `* hard core 0` to /etc/security/limits.conf.",
                    module=self.module_name,
                    check_id="sys-009",
                ))
        return findings

    def _check_swap_usage(self) -> List[Finding]:
        findings = []
        meminfo = _read("/proc/meminfo")
        swap_total, swap_free = 0, 0
        for line in meminfo.splitlines():
            if line.startswith("SwapTotal:"):
                swap_total = int(line.split()[1])
            elif line.startswith("SwapFree:"):
                swap_free = int(line.split()[1])

        if swap_total == 0:
            findings.append(Finding(
                title="No swap space configured",
                severity=Severity.LOW,
                category="System Health",
                description=(
                    "The system has no swap partition or swap file. Without swap, "
                    "the OOM killer will be triggered earlier when memory pressure occurs."
                ),
                evidence="SwapTotal: 0 kB",
                remediation="Create a swap file: `fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile`.",
                module=self.module_name,
                check_id="sys-010",
            ))
        elif swap_total > 0:
            swap_used_pct = ((swap_total - swap_free) / swap_total) * 100
            if swap_used_pct > 80:
                findings.append(Finding(
                    title=f"Swap usage critically high ({swap_used_pct:.0f}%)",
                    severity=Severity.HIGH,
                    category="System Health",
                    description="Swap usage is above 80%, indicating severe memory pressure.",
                    evidence=f"SwapTotal: {swap_total} kB, SwapFree: {swap_free} kB, Used: {swap_used_pct:.1f}%",
                    remediation="Investigate memory-hungry processes with `top` or `htop`. Consider adding RAM.",
                    module=self.module_name,
                    check_id="sys-011",
                ))
        return findings

    def _check_load_average(self) -> List[Finding]:
        findings = []
        loadavg = _read("/proc/loadavg")
        cpuinfo = _read("/proc/cpuinfo")
        if not loadavg:
            return []

        cpu_count = cpuinfo.count("processor\t:")
        if cpu_count == 0:
            cpu_count = 1

        try:
            load_1, load_5, load_15 = [float(x) for x in loadavg.split()[:3]]
        except (ValueError, IndexError):
            return []

        if load_5 > cpu_count * 2:
            findings.append(Finding(
                title=f"System severely overloaded (load avg: {load_5:.1f}, CPUs: {cpu_count})",
                severity=Severity.HIGH,
                category="Performance",
                description=(
                    f"The 5-minute load average ({load_5:.1f}) is more than double the CPU count ({cpu_count}). "
                    "The system is severely overloaded and processes are queuing for CPU time."
                ),
                evidence=f"Load averages: 1min={load_1:.2f}, 5min={load_5:.2f}, 15min={load_15:.2f} | CPUs: {cpu_count}",
                remediation="Identify CPU-hungry processes with `top` or `htop`. Consider scaling up.",
                module=self.module_name,
                check_id="sys-012",
            ))
        elif load_5 > cpu_count:
            findings.append(Finding(
                title=f"System under high load (load avg: {load_5:.1f}, CPUs: {cpu_count})",
                severity=Severity.MEDIUM,
                category="Performance",
                description=f"The 5-minute load average ({load_5:.1f}) exceeds the CPU count ({cpu_count}).",
                evidence=f"Load averages: 1min={load_1:.2f}, 5min={load_5:.2f}, 15min={load_15:.2f} | CPUs: {cpu_count}",
                remediation="Monitor CPU usage and investigate high-load processes.",
                module=self.module_name,
                check_id="sys-013",
            ))
        return findings
