"""Module 17: User Account Security Auditing.

Checks:
  - Dormant accounts (no login for 90+ days)
  - Duplicate UIDs
  - Accounts with empty passwords in /etc/shadow
  - Home directory permissions
  - Service accounts with interactive login shells
"""
from __future__ import annotations
import subprocess
import os
import stat
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity

try:
    import pwd as _pwd
    _HAS_PWD = True
except ImportError:
    _HAS_PWD = False


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


class UserChecker(Checker):
    module_name = "user_accounts"

    def list_checks(self) -> List[str]:
        return [
            "Detect dormant user accounts (no login for 90+ days)",
            "Detect duplicate UIDs across user accounts",
            "Find accounts with empty/blank passwords in /etc/shadow",
            "Audit home directory permissions for all users",
            "Flag service accounts with interactive login shells",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_dormant_accounts()
        findings += self._check_duplicate_uids()
        findings += self._check_empty_passwords()
        findings += self._check_home_permissions()
        findings += self._check_login_shells()
        return findings

    def _check_dormant_accounts(self) -> List[Finding]:
        findings = []
        out = _run(["lastlog", "-b", "90"])
        dormant = []
        for line in out.splitlines()[1:]:  # skip header
            parts = line.split()
            if not parts:
                continue
            username = parts[0]
            # Skip system accounts
            if username in ("root", "daemon", "bin", "sys", "sync", "games",
                            "man", "lp", "mail", "news", "uucp", "proxy",
                            "www-data", "backup", "list", "irc", "gnats",
                            "nobody", "systemd-network", "systemd-resolve",
                            "messagebus", "systemd-timesync", "syslog",
                            "_apt", "tss", "uuidd", "avahi-autoipd",
                            "usbmux", "rtkit", "dnsmasq", "avahi",
                            "cups-pk-helper", "speech-dispatcher", "fwupd-refresh",
                            "saned", "colord", "geoclue", "pulse", "gnome-initial-setup",
                            "gdm", "hplip"):
                continue
            if "Never logged in" in line:
                dormant.append(f"{username}: Never logged in")

        if dormant:
            findings.append(Finding(
                title=f"Dormant user accounts detected ({len(dormant)} accounts)",
                severity=Severity.MEDIUM,
                category="Security",
                description=(
                    "User accounts exist that have never logged in or haven't logged in "
                    "for over 90 days. Dormant accounts increase the attack surface as they "
                    "may have weak or default passwords and won't be noticed if compromised."
                ),
                evidence="\n".join(dormant[:15]),
                remediation="Lock dormant accounts: `usermod -L <username>` or delete them: `userdel -r <username>`.",
                module=self.module_name,
                check_id="usr-001",
            ))
        return findings

    def _check_duplicate_uids(self) -> List[Finding]:
        findings = []
        passwd = _read("/etc/passwd")
        if not passwd:
            return []

        uid_map: dict = {}
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 4:
                continue
            username, uid = parts[0], parts[2]
            uid_map.setdefault(uid, []).append(username)

        dupes = {uid: users for uid, users in uid_map.items() if len(users) > 1}
        if dupes:
            evidence_lines = [f"UID {uid}: {', '.join(users)}" for uid, users in dupes.items()]
            findings.append(Finding(
                title="Duplicate UIDs detected",
                severity=Severity.HIGH,
                category="Security",
                risk_score=80,
                description=(
                    "Multiple user accounts share the same UID. This means they have "
                    "identical filesystem permissions and can access each other's files. "
                    "This is a serious security misconfiguration often used for backdoor access."
                ),
                evidence="\n".join(evidence_lines),
                remediation="Assign unique UIDs to each account using `usermod -u <new_uid> <username>`.",
                module=self.module_name,
                check_id="usr-002",
            ))
        return findings

    def _check_empty_passwords(self) -> List[Finding]:
        findings = []
        shadow = _read("/etc/shadow")
        if not shadow:
            return []

        empty_pw = []
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            username, pw_hash = parts[0], parts[1]
            # Empty password field or just empty string
            if pw_hash in ("", "!", "!!", "*"):
                continue  # locked or no-login accounts
            if pw_hash == "":
                empty_pw.append(username)

        if empty_pw:
            findings.append(Finding(
                title="Accounts with empty passwords",
                severity=Severity.CRITICAL,
                category="Security",
                risk_score=98,
                description=(
                    "User accounts were found with completely empty password hashes in /etc/shadow. "
                    "Anyone can log into these accounts without entering a password."
                ),
                evidence="\n".join(empty_pw),
                remediation="Lock these accounts: `passwd -l <username>` or set a strong password.",
                module=self.module_name,
                check_id="usr-003",
            ))
        return findings

    def _check_home_permissions(self) -> List[Finding]:
        findings = []
        passwd = _read("/etc/passwd")
        if not passwd:
            return []

        insecure_homes = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, uid, home = parts[0], int(parts[2]), parts[5]

            # Skip system accounts (UID < 1000) and nologin
            if uid < 1000 or home in ("/", "/nonexistent", "/dev/null", ""):
                continue
            if not os.path.exists(home):
                continue

            try:
                st = os.stat(home)
                mode = st.st_mode
                # Check if group-writable or world-readable/writable
                issues = []
                if mode & stat.S_IWGRP:
                    issues.append("group-writable")
                if mode & stat.S_IWOTH:
                    issues.append("world-writable")
                if mode & stat.S_IROTH:
                    issues.append("world-readable")
                if issues:
                    perm_str = oct(mode & 0o777)
                    insecure_homes.append(f"{home} ({username}): {perm_str} - {', '.join(issues)}")
            except OSError:
                continue

        if insecure_homes:
            findings.append(Finding(
                title="Insecure home directory permissions",
                severity=Severity.MEDIUM,
                category="Security",
                description=(
                    "User home directories have overly permissive permissions. "
                    "Other users can read private files (SSH keys, configs, browser data) "
                    "or write files (planting malicious scripts)."
                ),
                evidence="\n".join(insecure_homes[:15]),
                remediation="Fix permissions: `chmod 700 /home/<user>` or at most `chmod 750 /home/<user>`.",
                module=self.module_name,
                check_id="usr-004",
            ))
        return findings

    def _check_login_shells(self) -> List[Finding]:
        findings = []
        passwd = _read("/etc/passwd")
        if not passwd:
            return []

        interactive_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish",
                              "/usr/bin/bash", "/usr/bin/sh", "/usr/bin/zsh", "/usr/bin/fish"}
        # System users that should NOT have interactive shells
        system_users = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, uid, shell = parts[0], int(parts[2]), parts[6].strip()
            # System accounts (UID < 1000) with interactive shells
            if uid < 1000 and uid != 0 and shell in interactive_shells:
                system_users.append(f"{username} (UID {uid}): shell={shell}")

        if system_users:
            findings.append(Finding(
                title="Service accounts with interactive login shells",
                severity=Severity.MEDIUM,
                category="Security",
                description=(
                    "System/service accounts have interactive login shells assigned. "
                    "If an attacker compromises a service running as one of these accounts, "
                    "they get a full interactive shell. Service accounts should use /usr/sbin/nologin."
                ),
                evidence="\n".join(system_users[:15]),
                remediation="Set nologin shell: `usermod -s /usr/sbin/nologin <username>`.",
                module=self.module_name,
                check_id="usr-005",
            ))
        return findings
