"""Module 12: Running Process Security.

Checks:
  - Processes executing from suspicious directories (/tmp, /dev/shm, /var/tmp)
  - Processes with world-writable executable paths (binary replacement risk)
  - Unexpected root processes (compared against a known-good baseline list)
  - Processes holding open suspicious network connections
  - Processes with deleted executable files (possible in-memory malware)
"""
from __future__ import annotations
import os
import re
import subprocess
from pathlib import Path
from typing import List, Set
from core.models import Checker, Finding, Severity


def _run(cmd: List[str], timeout: int = 15) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


# Processes that legitimately run as root — not flagged
_EXPECTED_ROOT_PROCS: Set[str] = {
    "systemd", "init", "kthreadd", "ksoftirqd", "kworker", "rcu_sched",
    "rcu_bh", "migration", "watchdog", "cpuhp", "netns", "kdevtmpfs",
    "khungtaskd", "oom_reaper", "writeback", "kcompactd", "kswapd",
    "kthrotld", "irq", "acpi_thermal", "scsi_eh", "scsi_tmf",
    "kdmflush", "bioset", "jbd2", "ext4-rsv-conver",
    "sshd", "cron", "crond", "rsyslogd", "journald", "systemd-journal",
    "systemd-udevd", "systemd-logind", "systemd-networkd", "systemd-resolved",
    "dbus-daemon", "polkitd", "accounts-daemon", "NetworkManager",
    "dockerd", "containerd", "kubelet",
    "python3", "python",  # vulnscan itself
    "auditd", "agetty", "login",
    "apache2", "httpd", "nginx",
    "mysqld", "postgres", "mongod",
    "ntpd", "chronyd",
}

_SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/dev/mqueue"]


class ProcessChecker(Checker):
    module_name = "process_security"

    def list_checks(self) -> List[str]:
        return [
            "Find processes executing from suspicious directories (/tmp, /dev/shm)",
            "Find processes with world-writable executable paths",
            "Find processes with deleted executables (possible in-memory implants)",
            "Audit unexpected root processes (compare to known-good list)",
            "Summarise outbound network connections from processes",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        procs = self._enumerate_processes()
        if not procs:
            return [Finding(
                title="Could not enumerate processes",
                severity=Severity.INFO,
                description=(
                    "Could not read /proc/<pid>/exe — likely insufficient permissions. "
                    "Re-run as root for complete process inspection."
                ),
                module=self.module_name,
                check_id="proc-000",
            )]
        findings += self._check_suspicious_dir_procs(procs)
        findings += self._check_writable_exe_procs(procs)
        findings += self._check_deleted_exe_procs(procs)
        findings += self._check_unexpected_root_procs(procs)
        findings += self._check_outbound_connections()
        return findings

    # ── Process enumeration ───────────────────────────────────────────────────

    def _enumerate_processes(self) -> List[dict]:
        """Walk /proc and collect pid, exe, cmdline, uid for each process."""
        procs = []
        proc_dir = Path("/proc")
        if not proc_dir.exists():
            return procs
        for entry in proc_dir.iterdir():
            if not entry.name.isdigit():
                continue
            pid = entry.name
            try:
                exe_path = str(os.readlink(f"/proc/{pid}/exe"))
            except (OSError, PermissionError):
                exe_path = ""
            try:
                cmdline = (
                    Path(f"/proc/{pid}/cmdline")
                    .read_bytes()
                    .replace(b"\x00", b" ")
                    .decode(errors="replace")
                    .strip()
                )
            except (OSError, PermissionError):
                cmdline = ""
            try:
                status = Path(f"/proc/{pid}/status").read_text(errors="replace")
                uid_line = next(
                    (l for l in status.splitlines() if l.startswith("Uid:")), ""
                )
                uid = int(uid_line.split()[1]) if uid_line else -1
                name_line = next(
                    (l for l in status.splitlines() if l.startswith("Name:")), ""
                )
                name = name_line.split(":", 1)[1].strip() if name_line else ""
            except (OSError, PermissionError, StopIteration, ValueError, IndexError):
                uid = -1
                name = ""

            procs.append({
                "pid": pid,
                "exe": exe_path,
                "cmdline": cmdline[:200],
                "uid": uid,
                "name": name,
            })
        if self.logger:
            self.logger.info(
                f"[{self.module_name}] enumerated {len(procs)} processes"
            )
        return procs

    # ── Individual checks ────────────────────────────────────────────────────

    def _check_suspicious_dir_procs(self, procs: List[dict]) -> List[Finding]:
        hits = []
        for p in procs:
            exe = p["exe"]
            if not exe:
                continue
            for suspect_dir in _SUSPICIOUS_DIRS:
                if exe.startswith(suspect_dir):
                    hits.append(
                        f"PID {p['pid']} ({p['name']}): {exe}\n"
                        f"  cmdline: {p['cmdline'][:80]}"
                    )
                    break
        if not hits:
            return []
        return [Finding(
            title=f"Processes running from suspicious directories ({len(hits)} found)",
            severity=Severity.CRITICAL,
            description=(
                f"{len(hits)} process(es) are executing from temporary or world-writable "
                f"directories (/tmp, /dev/shm, /var/tmp). This is a strong indicator of "
                f"malware, a dropped implant, or a container escape. Legitimate software "
                f"is never installed in these directories."
            ),
            evidence="\n".join(hits),
            remediation=(
                "Immediately investigate each process. Kill suspicious PIDs with "
                "`kill -9 <pid>`. Take a memory snapshot if forensics are needed "
                "before termination."
            ),
            module=self.module_name,
            check_id="proc-001",
        )]

    def _check_writable_exe_procs(self, procs: List[dict]) -> List[Finding]:
        hits = []
        for p in procs:
            exe = p["exe"]
            if not exe or " (deleted)" in exe:
                continue
            try:
                mode = Path(exe).stat().st_mode & 0o777
                if mode & 0o002:  # world-writable
                    hits.append(
                        f"PID {p['pid']} ({p['name']}): {exe} [{oct(mode)}]"
                    )
            except (OSError, PermissionError):
                continue
        if not hits:
            return []
        return [Finding(
            title=f"Processes with world-writable executables ({len(hits)} found)",
            severity=Severity.HIGH,
            description=(
                f"{len(hits)} process(es) are running executables that are world-writable. "
                f"Any local user can overwrite the binary to execute arbitrary code the "
                f"next time the process restarts."
            ),
            evidence="\n".join(hits),
            remediation=(
                "Remove world-write permission: `chmod o-w <exe_path>`. "
                "Executables should be owned by root with mode 755 or stricter."
            ),
            module=self.module_name,
            check_id="proc-002",
        )]

    def _check_deleted_exe_procs(self, procs: List[dict]) -> List[Finding]:
        """Processes whose on-disk binary has been deleted — classic implant technique."""
        hits = []
        for p in procs:
            exe = p["exe"]
            if exe and " (deleted)" in exe:
                # Exclude known benign deleted-exe patterns (e.g. systemd-private)
                if "systemd-private" in exe or "snap" in exe:
                    continue
                hits.append(
                    f"PID {p['pid']} ({p['name']}): {exe}\n"
                    f"  cmdline: {p['cmdline'][:80]}"
                )
        if not hits:
            return []
        return [Finding(
            title=f"Processes with deleted executables ({len(hits)} found)",
            severity=Severity.HIGH,
            description=(
                f"{len(hits)} process(es) are running but their on-disk executable has "
                f"been deleted. This is a common technique used by malware and rootkits "
                f"to evade file-based detection — the binary runs from memory after the "
                f"file is unlinked."
            ),
            evidence="\n".join(hits),
            remediation=(
                "Investigate each process immediately. Use `ls -la /proc/<pid>/exe` "
                "and `cat /proc/<pid>/cmdline` to identify what is running. "
                "Consider taking a memory dump with `gcore <pid>` before killing."
            ),
            module=self.module_name,
            check_id="proc-003",
        )]

    def _check_unexpected_root_procs(self, procs: List[dict]) -> List[Finding]:
        unexpected = []
        for p in procs:
            if p["uid"] != 0:
                continue
            name = p["name"].lower()
            if not name:
                continue
            # Strip common suffixes like numbers, dashes
            base = re.sub(r"[\d\-_]+$", "", name)
            if base not in _EXPECTED_ROOT_PROCS and name not in _EXPECTED_ROOT_PROCS:
                exe = p["exe"] or "(unknown)"
                unexpected.append(
                    f"PID {p['pid']} ({p['name']}): {exe}"
                )
        if not unexpected:
            return []
        return [Finding(
            title=f"Unexpected root processes ({len(unexpected)} found)",
            severity=Severity.MEDIUM,
            description=(
                f"{len(unexpected)} root process(es) are not in the known-good list. "
                f"This may be legitimate software not in the baseline, or it may "
                f"indicate a privilege escalation or persistence mechanism. "
                f"Manual verification is required."
            ),
            evidence="\n".join(unexpected[:30]),
            remediation=(
                "Review each process. If legitimate, no action needed. "
                "If unexpected, investigate for signs of compromise: "
                "check parent PID, open files (/proc/<pid>/fd), and network connections."
            ),
            module=self.module_name,
            check_id="proc-004",
        )]

    def _check_outbound_connections(self) -> List[Finding]:
        """List established outbound connections as an inventory finding."""
        out = _run(["ss", "-tnp", "state", "established"]) or \
              _run(["netstat", "-tnp"])
        if not out.strip():
            return []
        lines = [l for l in out.splitlines() if l.strip() and "Local Address" not in l]
        if not lines:
            return []
        if self.logger:
            self.logger.info(
                f"[{self.module_name}] {len(lines)} established connections found"
            )
        return [Finding(
            title=f"Established network connections inventory ({len(lines)} connections)",
            severity=Severity.INFO,
            description=(
                "List of currently established TCP connections. Review for any "
                "unexpected outbound connections to external IPs or unusual ports, "
                "which may indicate C2 callbacks or data exfiltration."
            ),
            evidence=out[:3000],
            remediation=(
                "Investigate any connections to unexpected external IPs. "
                "Use `ss -tnp` or `netstat -tnp` to correlate with process names."
            ),
            module=self.module_name,
            check_id="proc-005",
        )]
