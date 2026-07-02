"""Module 13: NFS, SMB/Samba & Shared File Systems.

Checks:
  - /etc/exports: no_root_squash, insecure, world-accessible exports
  - NFS service running unnecessarily
  - Samba smb.conf: guest ok, writable shares, null passwords
  - showmount: actively visible exports
  - rpcbind exposure
"""
from __future__ import annotations
import re
import shutil
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _run(cmd: List[str], timeout: int = 10) -> str:
    import subprocess
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


class NfsChecker(Checker):
    module_name = "nfs_smb_shares"

    def list_checks(self) -> List[str]:
        return [
            "Parse /etc/exports for no_root_squash, insecure, world-accessible exports",
            "Check NFS and rpcbind service status",
            "Parse Samba smb.conf for guest access and writable public shares",
            "Run showmount -e to enumerate visible NFS exports",
            "Check /etc/samba/smbpasswd for empty passwords",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_nfs_exports()
        findings += self._check_nfs_services()
        findings += self._check_samba()
        findings += self._check_showmount()
        return findings

    # ── /etc/exports ──────────────────────────────────────────────────────────

    def _check_nfs_exports(self) -> List[Finding]:
        content = _read("/etc/exports")
        if not content.strip():
            return []

        findings: List[Finding] = []
        no_root_squash_entries: List[str] = []
        insecure_entries: List[str] = []
        world_accessible: List[str] = []

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # no_root_squash lets root on the client act as root on the server
            if "no_root_squash" in stripped:
                no_root_squash_entries.append(stripped)

            # insecure allows connections from non-privileged ports (> 1024)
            if "insecure" in stripped and "insecure_locks" not in stripped:
                insecure_entries.append(stripped)

            # World-accessible: export to * or 0.0.0.0/0 or no host restriction
            parts = stripped.split()
            if parts:
                host_spec = ""
                # Host specs are in parens, e.g. /share *(rw,no_root_squash)
                # or /share hostname(rw)
                m = re.match(r"^\S+\s+(\S+)\(", stripped)
                if m:
                    host_spec = m.group(1)
                # World-accessible if host is *, 0.0.0.0, or bare paren
                if host_spec in ("*", "0.0.0.0", "") or "*(rw" in stripped:
                    world_accessible.append(stripped)

        if no_root_squash_entries:
            findings.append(Finding(
                title="NFS exports with no_root_squash",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(no_root_squash_entries)} NFS export(s) have no_root_squash set. "
                    f"This allows a root user on the NFS client to read and write files "
                    f"as root on the server, completely bypassing file permission controls. "
                    f"This is one of the most severe NFS misconfigurations — it trivially "
                    f"leads to full host compromise from any allowed client."
                ),
                evidence="\n".join(no_root_squash_entries),
                remediation=(
                    "Remove no_root_squash from all exports. The default (root_squash) "
                    "maps client root to the anonymous user. "
                    "If you must allow root access, use all_squash + anonuid/anongid instead."
                ),
                cis_refs=["CIS Linux 2.2.7"],
                cve_refs=["CVE-2019-14899"],
                module=self.module_name,
                check_id="nfs-001",
            ))

        if insecure_entries:
            findings.append(Finding(
                title="NFS exports with 'insecure' option",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(insecure_entries)} NFS export(s) use the 'insecure' option, "
                    f"allowing connections from client ports above 1024. "
                    f"Unprivileged processes on the client can originate NFS connections."
                ),
                evidence="\n".join(insecure_entries),
                remediation=(
                    "Remove the 'insecure' option from exports to require privileged "
                    "source ports (< 1024), which typically require root on the client."
                ),
                module=self.module_name,
                check_id="nfs-002",
            ))

        if world_accessible:
            findings.append(Finding(
                title="NFS exports accessible to all hosts (*)",
                severity=Severity.HIGH,
                description=(
                    f"{len(world_accessible)} NFS export(s) allow connections from any "
                    f"host (*). Any system on the network can mount these shares."
                ),
                evidence="\n".join(world_accessible),
                remediation=(
                    "Restrict each export to specific trusted hosts or subnets: "
                    "/share 192.168.1.0/24(ro,root_squash)"
                ),
                module=self.module_name,
                check_id="nfs-003",
            ))

        if not findings:
            findings.append(Finding(
                title="NFS exports configured (manual review recommended)",
                severity=Severity.INFO,
                description="/etc/exports exists. No critical misconfigurations auto-detected.",
                evidence=content[:500],
                module=self.module_name,
                check_id="nfs-001",
            ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] /etc/exports checked")
        return findings

    # ── NFS service status ─────────────────────────────────────────────────────

    def _check_nfs_services(self) -> List[Finding]:
        findings: List[Finding] = []

        # rpcbind exposes a portmapper service — flag if world-accessible
        rpcbind_active = _run(["systemctl", "is-active", "rpcbind"]).strip()
        nfs_active     = _run(["systemctl", "is-active", "nfs-server"]).strip()

        if rpcbind_active == "active" and not Path("/etc/exports").exists():
            findings.append(Finding(
                title="rpcbind running with no NFS exports defined",
                severity=Severity.LOW,
                description=(
                    "rpcbind is active but /etc/exports does not exist. "
                    "If NFS is not used, rpcbind is unnecessary attack surface."
                ),
                remediation="Disable rpcbind: `systemctl disable --now rpcbind`",
                cis_refs=["CIS Linux 2.2.7"],
                module=self.module_name,
                check_id="nfs-004",
            ))

        if nfs_active == "active":
            exports = _read("/etc/exports").strip()
            if not exports:
                findings.append(Finding(
                    title="NFS server running with empty exports file",
                    severity=Severity.LOW,
                    description=(
                        "nfs-server service is active but /etc/exports is empty. "
                        "If NFS is not needed, disable it."
                    ),
                    remediation="systemctl disable --now nfs-server rpcbind",
                    module=self.module_name,
                    check_id="nfs-004",
                ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] NFS service status checked")
        return findings

    # ── Samba / SMB ───────────────────────────────────────────────────────────

    def _check_samba(self) -> List[Finding]:
        smb_paths = ["/etc/samba/smb.conf", "/etc/smb.conf"]
        content = ""
        used_path = ""
        for p in smb_paths:
            content = _read(p)
            if content:
                used_path = p
                break
        if not content:
            return []

        findings: List[Finding] = []
        current_share = "[global]"
        guest_ok_shares: List[str] = []
        writable_guest_shares: List[str] = []
        null_passwords = False

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            # Detect share section header
            m = re.match(r"^\[(.+)\]$", stripped)
            if m:
                current_share = stripped
                continue
            # Key = value
            kv = re.match(r"^(.+?)\s*=\s*(.+)$", stripped)
            if not kv:
                continue
            key, val = kv.group(1).strip().lower(), kv.group(2).strip().lower()

            if key == "guest ok" and val in ("yes", "true", "1"):
                guest_ok_shares.append(current_share)
            if key in ("writable", "write ok", "read only") and val in ("yes", "true", "1", "no"):
                # writable=yes or read only=no means writable
                if (key in ("writable", "write ok") and val in ("yes", "true", "1")) or \
                   (key == "read only" and val == "no"):
                    if current_share in guest_ok_shares:
                        writable_guest_shares.append(current_share)
            if key == "null passwords" and val in ("yes", "true", "1"):
                null_passwords = True

        if guest_ok_shares:
            findings.append(Finding(
                title=f"Samba shares with guest access enabled ({len(guest_ok_shares)})",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(guest_ok_shares)} Samba share(s) have 'guest ok = yes'. "
                    f"Unauthenticated users can access these shares."
                ),
                evidence="\n".join(guest_ok_shares),
                remediation=(
                    "Set 'guest ok = no' for all shares that should require authentication. "
                    "Only enable guest access for intentionally public shares."
                ),
                cis_refs=["CIS Linux 2.2.12"],
                module=self.module_name,
                check_id="nfs-005",
            ))

        if writable_guest_shares:
            findings.append(Finding(
                title=f"Samba shares that are guest-writable ({len(writable_guest_shares)})",
                severity=Severity.HIGH,
                description=(
                    f"{len(writable_guest_shares)} Samba share(s) are both guest-accessible "
                    f"and writable. Any unauthenticated user on the network can write arbitrary "
                    f"files to these shares."
                ),
                evidence="\n".join(writable_guest_shares),
                remediation=(
                    "Either require authentication (guest ok = no) or make the share "
                    "read-only for guests (read only = yes)."
                ),
                module=self.module_name,
                check_id="nfs-006",
            ))

        if null_passwords:
            findings.append(Finding(
                title="Samba 'null passwords' enabled in smb.conf",
                severity=Severity.CRITICAL,
                description=(
                    "smb.conf has 'null passwords = yes'. Users with blank passwords "
                    "can authenticate to Samba, completely bypassing password requirements."
                ),
                evidence=f"{used_path}: null passwords = yes",
                remediation=(
                    "Remove or set 'null passwords = no' in smb.conf. "
                    "Ensure all Samba user accounts have passwords set."
                ),
                module=self.module_name,
                check_id="nfs-007",
            ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] Samba config checked: {used_path}")
        return findings

    # ── showmount ─────────────────────────────────────────────────────────────

    def _check_showmount(self) -> List[Finding]:
        if not shutil.which("showmount"):
            return []
        out = _run(["showmount", "-e", "localhost"], timeout=5)
        if not out.strip():
            return []
        exports = [l for l in out.splitlines() if l.strip() and "Export list" not in l]
        if not exports:
            return []
        return [Finding(
            title=f"NFS exports visible via showmount ({len(exports)} entries)",
            severity=Severity.INFO,
            description=(
                "showmount -e localhost returned active NFS exports. "
                "Cross-reference with /etc/exports findings above."
            ),
            evidence=out.strip(),
            module=self.module_name,
            check_id="nfs-008",
        )]
