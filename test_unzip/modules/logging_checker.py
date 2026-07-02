"""Module 8: Logging, Auditing & Monitoring."""
from __future__ import annotations
import subprocess
import shutil
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity


def _run(cmd: List[str], timeout: int = 10) -> str:
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


def _read_dir(dir_path: str, glob: str = "*.conf") -> str:
    """Read and concatenate all files matching glob in a directory."""
    p = Path(dir_path)
    if not p.is_dir():
        return ""
    content = ""
    for f in p.glob(glob):
        content += _read(str(f))
    return content


class LoggingChecker(Checker):
    module_name = "logging_auditing"

    def list_checks(self) -> List[str]:
        return [
            "Check auditd installation and service status",
            "Check audit rules for privilege escalation events",
            "Check syslog / journald configuration",
            "Check log file permissions (tamper evidence)",
            "Check log rotation configuration",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_auditd()
        findings += self._check_audit_rules()
        findings += self._check_syslog()
        findings += self._check_log_permissions()
        findings += self._check_log_rotation()
        return findings

    def _check_auditd(self) -> List[Finding]:
        if not shutil.which("auditctl"):
            return [Finding(
                title="auditd not installed",
                severity=Severity.HIGH,
                description=(
                    "auditd is not present on this system. Without it, privilege "
                    "escalation, file access, and authentication events are not "
                    "captured in a tamper-evident audit trail."
                ),
                remediation=(
                    "Install auditd: `apt install auditd` or `dnf install audit`, "
                    "then enable and start the service."
                ),
                cis_refs=["CIS Linux 4.1.1"],
                module=self.module_name,
                check_id="log-001",
            )]
        status = _run(["systemctl", "is-active", "auditd"]).strip()
        if status != "active":
            return [Finding(
                title="auditd installed but not running",
                severity=Severity.HIGH,
                description=(
                    f"auditd service status: {status}. The audit daemon is not "
                    f"active; no audit events are being recorded."
                ),
                evidence=f"systemctl is-active auditd → {status}",
                remediation="Enable and start auditd: `systemctl enable --now auditd`",
                cis_refs=["CIS Linux 4.1.1"],
                module=self.module_name,
                check_id="log-001",
            )]
        return [Finding(
            title="auditd running",
            severity=Severity.INFO,
            description="auditd is installed and active.",
            module=self.module_name,
            check_id="log-001",
        )]

    def _check_audit_rules(self) -> List[Finding]:
        if not shutil.which("auditctl"):
            return []
        out = _run(["auditctl", "-l"])
        if not out.strip() or "No rules" in out:
            return [Finding(
                title="No audit rules configured",
                severity=Severity.HIGH,
                description=(
                    "auditd is running but has no rules defined. Key events like "
                    "privilege escalation, sudo usage, and sensitive file access are "
                    "not being captured."
                ),
                evidence=out.strip() or "(empty)",
                remediation=(
                    "Deploy a CIS-recommended audit ruleset via /etc/audit/rules.d/. "
                    "At minimum, audit: setuid/setgid execution, /etc/passwd writes, "
                    "sudo, su, and login events."
                ),
                cis_refs=["CIS Linux 4.1.6", "CIS Linux 4.1.7", "CIS Linux 4.1.8"],
                module=self.module_name,
                check_id="log-002",
            )]

        CRITICAL_RULES = [
            "-a always,exit -F arch=b64",
            "-w /etc/passwd",
            "-w /etc/shadow",
            "-w /etc/sudoers",
            "-w /var/log/",
            "/sbin/su",
            "/usr/bin/sudo",
        ]
        missing = [r for r in CRITICAL_RULES if r not in out]
        if missing:
            return [Finding(
                title="Audit rules missing for critical events",
                severity=Severity.MEDIUM,
                description=(
                    "auditd is configured but missing rules for some critical paths. "
                    "Events like shadow/sudoers modifications may go unlogged."
                ),
                evidence="Missing rule patterns:\n" + "\n".join(missing),
                remediation=(
                    "Add rules for the missing paths/syscalls in /etc/audit/rules.d/."
                ),
                cis_refs=["CIS Linux 4.1"],
                module=self.module_name,
                check_id="log-002",
            )]
        return []

    def _check_syslog(self) -> List[Finding]:
        has_rsyslog = shutil.which("rsyslogd") is not None
        has_syslog  = shutil.which("syslogd") is not None
        journald    = Path("/run/systemd/journal").exists()

        if not any([has_rsyslog, has_syslog, journald]):
            return [Finding(
                title="No syslog daemon or journald detected",
                severity=Severity.HIGH,
                description=(
                    "No syslog daemon (rsyslog, syslogd) or systemd-journald detected. "
                    "System events may not be persisted anywhere."
                ),
                remediation="Install rsyslog: `apt install rsyslog` and enable it.",
                cis_refs=["CIS Linux 4.2"],
                module=self.module_name,
                check_id="log-003",
            )]

        if journald:
            # Correctly read both the main conf file AND all drop-in files in .conf.d/
            storage_config = _read("/etc/systemd/journald.conf")
            storage_config += _read_dir("/etc/systemd/journald.conf.d", "*.conf")
            if "Storage=volatile" in storage_config:
                return [Finding(
                    title="journald configured with volatile (RAM-only) storage",
                    severity=Severity.MEDIUM,
                    description=(
                        "journald is storing logs in RAM only. All logs are lost on "
                        "reboot, making post-incident forensics impossible."
                    ),
                    evidence="Storage=volatile in journald.conf",
                    remediation="Set Storage=persistent in /etc/systemd/journald.conf",
                    cis_refs=["CIS Linux 4.2.1"],
                    module=self.module_name,
                    check_id="log-003",
                )]
        return []

    def _check_log_permissions(self) -> List[Finding]:
        log_files = [
            "/var/log/auth.log", "/var/log/secure",
            "/var/log/syslog", "/var/log/messages",
            "/var/log/audit/audit.log",
        ]
        findings = []
        for lf in log_files:
            p = Path(lf)
            if not p.exists():
                continue
            mode = p.stat().st_mode & 0o777
            if mode & 0o002:  # world-writable
                findings.append(Finding(
                    title=f"Log file world-writable: {lf}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"{lf} is world-writable. An attacker can tamper with or "
                        f"truncate audit evidence after a compromise."
                    ),
                    evidence=f"{lf}: {oct(mode)}",
                    remediation=f"chmod 640 {lf} (or 600 for audit.log); chown root:adm.",
                    cis_refs=["CIS Linux 4.2.3"],
                    module=self.module_name,
                    check_id="log-004",
                ))
        if self.logger:
            self.logger.info(f"[{self.module_name}] log permission check done")
        return findings

    def _check_log_rotation(self) -> List[Finding]:
        if not Path("/etc/logrotate.conf").exists():
            return [Finding(
                title="logrotate not configured",
                severity=Severity.LOW,
                description=(
                    "No /etc/logrotate.conf found. Log files may grow unbounded, "
                    "risking disk exhaustion which itself can suppress future logging."
                ),
                remediation=(
                    "Install and configure logrotate with appropriate retention periods."
                ),
                cis_refs=["CIS Linux 4.2.2"],
                module=self.module_name,
                check_id="log-005",
            )]
        return []
