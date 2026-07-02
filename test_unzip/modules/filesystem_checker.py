"""Module 7: File System, Permissions & Storage."""
from __future__ import annotations
import os
import subprocess
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


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError):
        return ""


class FilesystemChecker(Checker):
    module_name = "filesystem_permissions"

    def list_checks(self) -> List[str]:
        return [
            "Find world-writable files and directories",
            "Find world-writable UNIX domain sockets",
            "Audit dynamic linker configuration for Shared Library Hijacking",
            "Audit /etc/fstab for unmounted secondary/backup partitions",
            "Check sensitive file permissions (/etc/shadow, SSH keys, cron)",
            "Check mount options (noexec / nosuid / nodev on non-root mounts)",
            "Check disk encryption status (LUKS/dm-crypt)",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_world_writable()
        findings += self._check_world_writable_sockets()
        findings += self._check_ld_so_conf()
        findings += self._check_fstab_mounts()
        findings += self._check_sensitive_perms()
        findings += self._check_mount_options()
        findings += self._check_encryption()
        return findings

    def _check_world_writable(self) -> List[Finding]:
        out = _run(
            ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
             "!", "-path", "/proc/*", "!", "-path", "/sys/*"],
            timeout=120,
        )
        files = [ln for ln in out.strip().splitlines() if ln]
        if self.logger:
            self.logger.info(f"[{self.module_name}] world-writable files: {len(files)}")
        if files:
            return [Finding(
                title="World-writable files found",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(files)} world-writable files found. These can be modified "
                    f"by any local user, enabling privilege escalation via cron jobs, "
                    f"library injection, or config tampering."
                ),
                evidence="\n".join(files[:50]),
                remediation=(
                    "For each file, determine if world-write is needed; if not: "
                    "`chmod o-w <file>`. Pay special attention to any in /etc, /bin, "
                    "/usr/bin, or cron directories."
                ),
                cis_refs=["CIS Linux 6.1.10", "CIS Linux 6.1.11"],
                module=self.module_name,
                check_id="fs-001",
            )]
        return [Finding(
            title="No world-writable files found",
            severity=Severity.INFO,
            description="No world-writable regular files found (excl. /proc, /sys).",
            module=self.module_name,
            check_id="fs-001",
        )]

    def _check_sensitive_perms(self) -> List[Finding]:
        # max_mode: the loosest acceptable octal permission
        SENSITIVE = {
            "/etc/shadow":         (0o640, "0640", "shadow should be root:shadow 640 or stricter"),
            "/etc/passwd":         (0o644, "0644", "passwd should not be writable by non-root"),
            "/etc/gshadow":        (0o640, "0640", "gshadow same as shadow"),
            "/etc/crontab":        (0o600, "0600", "crontab should only be root-readable"),
            "/boot/grub/grub.cfg": (0o600, "0600", "grub.cfg should be root-only"),
        }
        findings = []
        for path, (max_mode, label, reason) in SENSITIVE.items():
            p = Path(path)
            try:
                mode = p.stat().st_mode & 0o777
            except PermissionError:
                findings.append(Finding(
                    title=f"Permission Denied: {path}",
                    severity=Severity.INFO,
                    description=f"Could not stat {path} due to insufficient permissions. Run as root for full coverage.",
                    module=self.module_name,
                    check_id="fs-002"
                ))
                continue
            except FileNotFoundError:
                continue
            
            if mode > max_mode:
                findings.append(Finding(
                    title=f"Overly permissive: {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{path} has permissions {oct(mode)}, "
                        f"looser than expected {label}. {reason}."
                    ),
                    evidence=f"{path}: {oct(mode)}",
                    remediation=f"chmod {label} {path}",
                    cis_refs=["CIS Linux 6.1"],
                    module=self.module_name,
                    check_id="fs-002",
                ))

        # SSH private host keys must be root-only (no group/other read/write/execute)
        ssh_dir = Path("/etc/ssh")
        for key in (ssh_dir.glob("ssh_host_*_key") if ssh_dir.exists() else []):
            mode = key.stat().st_mode & 0o777
            if mode & 0o077:  # any group or other permission bits set
                findings.append(Finding(
                    title=f"SSH host key accessible by non-root: {key.name}",
                    severity=Severity.HIGH,
                    description=(
                        f"{key} has permissions {oct(mode)}. SSH host private keys must "
                        f"be readable only by root to prevent impersonation."
                    ),
                    evidence=f"{key}: {oct(mode)}",
                    remediation=f"chmod 600 {key}",
                    cis_refs=["CIS Linux 5.2.1"],
                    module=self.module_name,
                    check_id="fs-003",
                ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] sensitive permissions checked")
        return findings

    def _check_mount_options(self) -> List[Finding]:
        mounts = _read("/proc/mounts")
        if not mounts:
            return []
        findings = []
        # Pseudo-filesystems that don't need noexec/nosuid/nodev
        SKIP_FSTYPES = {
            "proc", "sysfs", "tmpfs", "devtmpfs", "cgroup", "cgroup2",
            "debugfs", "securityfs", "hugetlbfs", "mqueue", "fusectl",
            "pstore", "efivarfs", "bpf",
        }
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            device, mountpoint, fstype, options = (
                parts[0], parts[1], parts[2], parts[3]
            )
            if mountpoint in ("/", "/boot") or fstype in SKIP_FSTYPES:
                continue
            opts = set(options.split(","))
            for missing, severity, reason in [
                ("noexec", Severity.MEDIUM, "allows execution of binaries on this mount"),
                ("nosuid", Severity.MEDIUM, "allows SUID binaries on this mount"),
                ("nodev",  Severity.LOW,    "allows device files on this mount"),
            ]:
                if missing not in opts:
                    findings.append(Finding(
                        title=f"Mount {mountpoint} missing {missing}",
                        severity=severity,
                        description=(
                            f"{mountpoint} ({device}, {fstype}) is mounted without "
                            f"{missing}, which {reason}."
                        ),
                        evidence=line,
                        remediation=(
                            f"Add {missing} to the mount options for {mountpoint} in "
                            f"/etc/fstab and remount."
                        ),
                        cis_refs=["CIS Linux 1.1"],
                        module=self.module_name,
                        check_id="fs-004",
                    ))
        return findings

    def _check_encryption(self) -> List[Finding]:
        out = _run(["lsblk", "-o", "NAME,TYPE,FSTYPE"])
        if "crypto_LUKS" in out or "dm-crypt" in out:
            return [Finding(
                title="LUKS disk encryption detected",
                severity=Severity.INFO,
                description="At least one partition appears to use LUKS/dm-crypt encryption.",
                evidence=out[:1000],
                module=self.module_name,
                check_id="fs-005",
            )]
        return [Finding(
            title="No disk encryption detected",
            severity=Severity.MEDIUM,
            description=(
                "No LUKS/dm-crypt encrypted partitions detected. Physical access to "
                "this VM image or disk gives unencrypted access to all data."
            ),
            evidence=out[:500] or "(lsblk output unavailable)",
            remediation=(
                "For sensitive VMs, use LUKS full-disk encryption. At minimum, encrypt "
                "partitions storing sensitive data."
            ),
            module=self.module_name,
            check_id="fs-005",
        )]

    def _check_ld_so_conf(self) -> List[Finding]:
        findings = []
        target_dirs = ["/etc/ld.so.conf.d"]
        
        # Check if the directory itself is writable
        for d in target_dirs:
            if not Path(d).exists():
                continue
                
            try:
                st = os.stat(d)
                if bool(st.st_mode & 0o0002):
                    findings.append(Finding(
                        title="Shared Library Hijacking (Writable ld.so.conf.d)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The dynamic linker configuration directory ({d}) is world-writable. "
                            "An attacker can drop a malicious .conf file here pointing to a directory "
                            "they control. All SUID binaries will then load malicious shared libraries "
                            "from the attacker's directory, granting instant root access."
                        ),
                        evidence=f"{d} is world-writable (mode {oct(st.st_mode)})",
                        remediation=f"chmod o-w {d}",
                        module=self.module_name,
                        check_id="fs-006",
                    ))
            except OSError:
                pass
                
        return findings

    def _check_fstab_mounts(self) -> List[Finding]:
        import re
        findings = []
        content = _read("/etc/fstab")
        if not content:
            return findings
            
        unmounted_backups = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Look for backup, secret, or old partitions that might not be mounted by default (noauto)
            # or just flagging them for review if they have sensitive names.
            if "backup" in line.lower() or "secret" in line.lower() or "old" in line.lower():
                unmounted_backups.append(line)
                
        if unmounted_backups:
            findings.append(Finding(
                title="Sensitive partitions found in /etc/fstab",
                severity=Severity.INFO,
                description=(
                    "The /etc/fstab file contains entries for partitions that sound like backups "
                    "or old file systems. If these are 'noauto' or mounted loosely, attackers "
                    "often find plaintext credentials or old SSH keys inside them."
                ),
                evidence="\n".join(unmounted_backups),
                remediation="Ensure backup partitions are securely encrypted and mounted with restricted permissions.",
                module=self.module_name,
                check_id="fs-007",
            ))
        return findings

    def _check_world_writable_sockets(self) -> List[Finding]:
        findings = []
        out = _run(["find", "/", "-type", "s", "-perm", "-0002", "-ls", "2>/dev/null"])
        if out and out.strip():
            sockets = out.strip().splitlines()
            findings.append(Finding(
                title="World-writable UNIX domain sockets",
                severity=Severity.HIGH,
                description="UNIX domain sockets with world-writable permissions were found. Attackers can connect to these sockets to interact with privileged services, potentially leading to LPE.",
                evidence="\n".join(sockets[:20]),
                remediation="Ensure sockets are created with restricted permissions or placed in protected directories.",
                module=self.module_name,
                check_id="fs-008",
            ))
        return findings
