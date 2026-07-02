"""Module 1: Kernel & Syscall Security."""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _run(cmd: List[str], timeout: int = 10) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


class KernelChecker(Checker):
    module_name = "kernel_syscall"

    def list_checks(self) -> List[str]:
        return [
            "Check kernel version (inventory for manual CVE cross-check)",
            "Check ptrace_scope (debug interface exposure)",
            "Check ASLR state (randomize_va_space)",
            "Check kptr_restrict (kernel pointer exposure)",
            "Check dmesg_restrict (kernel log access)",
            "Check seccomp availability",
            "Check SMEP / SMAP flags via /proc/cpuinfo",
            "Audit loaded kernel modules",
            "Check kernel version against known high-risk Local Privilege Escalation CVEs",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_kernel_version()
        findings += self._check_ptrace_scope()
        findings += self._check_aslr()
        findings += self._check_kptr_restrict()
        findings += self._check_dmesg_restrict()
        findings += self._check_seccomp()
        findings += self._check_smep_smap()
        findings += self._check_modules()
        findings += self._check_kernel_cves()
        return findings

    def _check_kernel_version(self) -> List[Finding]:
        version = _run(["uname", "-r"]).strip()
        if self.logger:
            self.logger.info(f"[{self.module_name}] kernel version: {version}")
        return [Finding(
            title="Kernel version inventory",
            severity=Severity.INFO,
            description=(
                f"Running kernel: {version}. Cross-check against your distro's "
                f"security tracker and NVD for unpatched CVEs against this build."
            ),
            evidence=version,
            remediation="Ensure this matches the latest patched kernel for your distro release.",
            module=self.module_name,
            check_id="kern-001",
        )]

    def _check_ptrace_scope(self) -> List[Finding]:
        val = _read("/proc/sys/kernel/yama/ptrace_scope")
        if val == "":
            return []
        if val == "0":
            return [Finding(
                title="ptrace_scope set to permissive (0)",
                severity=Severity.MEDIUM,
                description=(
                    "ptrace_scope=0 allows any process to ptrace any other process "
                    "owned by the same user, widening the attack surface for "
                    "credential theft / code injection between processes."
                ),
                evidence=f"/proc/sys/kernel/yama/ptrace_scope = {val}",
                remediation="Set kernel.yama.ptrace_scope=1 (or higher) via sysctl.",
                cis_refs=["CIS Linux 1.5.x"],
                module=self.module_name,
                check_id="kern-002",
            )]
        return [Finding(
            title="ptrace_scope restricted",
            severity=Severity.INFO,
            description=f"ptrace_scope = {val} (restricted).",
            module=self.module_name,
            check_id="kern-002",
        )]

    def _check_aslr(self) -> List[Finding]:
        val = _read("/proc/sys/kernel/randomize_va_space")
        if not val:
            return []
        if val != "2":
            return [Finding(
                title="ASLR not fully enabled",
                severity=Severity.HIGH,
                description=(
                    f"kernel.randomize_va_space = {val} (expected 2 for full ASLR). "
                    f"Reduced ASLR makes memory-corruption exploits significantly easier."
                ),
                evidence=f"/proc/sys/kernel/randomize_va_space = {val}",
                remediation="Set kernel.randomize_va_space=2 via sysctl.",
                cis_refs=["CIS Linux 1.5.3"],
                module=self.module_name,
                check_id="kern-003",
            )]
        return [Finding(
            title="ASLR fully enabled",
            severity=Severity.INFO,
            description="kernel.randomize_va_space = 2 (full ASLR).",
            module=self.module_name,
            check_id="kern-003",
        )]

    def _check_kptr_restrict(self) -> List[Finding]:
        val = _read("/proc/sys/kernel/kptr_restrict")
        if val == "0":
            return [Finding(
                title="Kernel pointer exposure (kptr_restrict=0)",
                severity=Severity.MEDIUM,
                description=(
                    "kptr_restrict=0 exposes kernel pointer addresses to unprivileged "
                    "users via /proc, aiding kernel exploit development (defeats KASLR)."
                ),
                evidence="/proc/sys/kernel/kptr_restrict = 0",
                remediation="Set kernel.kptr_restrict=1 (or 2) via sysctl.",
                cis_refs=["CIS Linux 1.5.1"],
                module=self.module_name,
                check_id="kern-004",
            )]
        return []

    def _check_dmesg_restrict(self) -> List[Finding]:
        val = _read("/proc/sys/kernel/dmesg_restrict")
        if val == "0":
            return [Finding(
                title="dmesg accessible to unprivileged users",
                severity=Severity.LOW,
                description=(
                    "dmesg_restrict=0 lets any local user read kernel logs, which can "
                    "leak addresses, hardware info, and driver bugs useful for exploitation."
                ),
                evidence="/proc/sys/kernel/dmesg_restrict = 0",
                remediation="Set kernel.dmesg_restrict=1 via sysctl.",
                cis_refs=["CIS Linux 1.5.2"],
                module=self.module_name,
                check_id="kern-005",
            )]
        return []

    def _check_seccomp(self) -> List[Finding]:
        # seccomp(2) availability is reflected in /proc/1/status
        status = _read("/proc/1/status")
        seccomp_line = next(
            (l for l in status.splitlines() if l.lower().startswith("seccomp")), ""
        )
        if seccomp_line:
            val = seccomp_line.split(":")[-1].strip()
            sev = Severity.INFO if val != "0" else Severity.LOW
            return [Finding(
                title="Seccomp status (PID 1)",
                severity=sev,
                description=f"PID 1 seccomp mode: {val} (0=disabled, 1=strict, 2=filter). "
                             "Containers and high-privilege services should use seccomp filtering.",
                evidence=seccomp_line,
                remediation="Apply seccomp profiles to privileged services and containers.",
                module=self.module_name,
                check_id="kern-006",
            )]
        return []

    def _check_smep_smap(self) -> List[Finding]:
        cpuinfo = _read("/proc/cpuinfo")
        findings = []
        for flag, name, desc in [
            ("smep", "SMEP", "Supervisor Mode Execution Prevention"),
            ("smap", "SMAP", "Supervisor Mode Access Prevention"),
        ]:
            present = flag in cpuinfo.lower()
            if not present:
                findings.append(Finding(
                    title=f"CPU does not advertise {name}",
                    severity=Severity.INFO,
                    description=(
                        f"{name} ({desc}) is not present in /proc/cpuinfo CPU flags. "
                        f"This may indicate a VM without CPU feature passthrough, or an "
                        f"older CPU without {name} support."
                    ),
                    evidence=f"{flag} not found in /proc/cpuinfo flags",
                    module=self.module_name,
                    check_id="kern-007",
                ))
        return findings

    def _check_modules(self) -> List[Finding]:
        out = _run(["lsmod"])
        count = max(len(out.strip().splitlines()) - 1, 0)
        if self.logger:
            self.logger.info(f"[{self.module_name}] {count} kernel modules loaded")
        return [Finding(
            title="Loaded kernel module inventory",
            severity=Severity.INFO,
            description=(
                f"{count} kernel modules currently loaded. Review for unnecessary "
                f"or unsigned out-of-tree modules increasing kernel attack surface."
            ),
            evidence=out[:2000],
            remediation=(
                "Blacklist unused modules (e.g. uncommon filesystems, legacy protocols) "
                "via /etc/modprobe.d/."
            ),
            module=self.module_name,
            check_id="kern-008",
        )]
