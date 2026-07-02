"""Module 11: Cron Jobs & Scheduled Task Security.

Checks:
  - Permissions on cron directories and system crontab
  - World-writable scripts referenced by cron entries
  - Scripts executed from world-writable directories
  - Cron entries running as root from user-controlled paths
  - at/batch job security
  - Cron access control (/etc/cron.allow / /etc/cron.deny)
"""
from __future__ import annotations
import subprocess
import re
from pathlib import Path
from typing import List, Tuple
from core.models import Checker, Finding, Severity


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _run(cmd: List[str], timeout: int = 15) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


# All system cron directories
SYSTEM_CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]

SYSTEM_CRONTAB = "/etc/crontab"


class CronChecker(Checker):
    module_name = "cron_scheduled_tasks"

    def list_checks(self) -> List[str]:
        return [
            "Check system crontab and cron directory permissions",
            "Find world-writable scripts called by cron",
            "Find cron scripts in world-writable directories",
            "Audit root cron entries for unsafe command paths",
            "Check cron.allow / cron.deny access control",
            "Check at/batch job access control",
            "Audit user crontabs for suspicious entries",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_cron_dir_permissions()
        findings += self._check_crontab_script_permissions()
        findings += self._check_root_cron_paths()
        findings += self._check_cron_access_control()
        findings += self._check_at_access_control()
        findings += self._check_user_crontabs()
        return findings

    # ── Directory & file permissions ──────────────────────────────────────────

    def _check_cron_dir_permissions(self) -> List[Finding]:
        findings: List[Finding] = []

        # /etc/crontab must be root-owned and not group/world writable
        ct = Path(SYSTEM_CRONTAB)
        if ct.exists():
            mode = ct.stat().st_mode & 0o777
            if mode & 0o022:  # group-write or world-write
                findings.append(Finding(
                    title="System crontab is group/world writable",
                    severity=Severity.HIGH,
                    description=(
                        f"/etc/crontab has permissions {oct(mode)}. Any user with "
                        f"write access can inject arbitrary commands that run as root."
                    ),
                    evidence=f"/etc/crontab: {oct(mode)}",
                    remediation="chmod 600 /etc/crontab; chown root:root /etc/crontab",
                    cis_refs=["CIS Linux 5.1.2"],
                    module=self.module_name,
                    check_id="cron-001",
                ))

        # Cron directories must not be group/world writable
        for dir_path in SYSTEM_CRON_DIRS:
            d = Path(dir_path)
            if not d.exists():
                continue
            mode = d.stat().st_mode & 0o777
            if mode & 0o022:
                findings.append(Finding(
                    title=f"Cron directory is group/world writable: {dir_path}",
                    severity=Severity.HIGH,
                    description=(
                        f"{dir_path} has permissions {oct(mode)}. An attacker with "
                        f"write access to this directory can drop a cron script that "
                        f"executes as root."
                    ),
                    evidence=f"{dir_path}: {oct(mode)}",
                    remediation=f"chmod 700 {dir_path}; chown root:root {dir_path}",
                    cis_refs=["CIS Linux 5.1.7"],
                    module=self.module_name,
                    check_id="cron-001",
                ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] cron directory permissions checked")
        return findings

    # ── World-writable scripts referenced by cron ────────────────────────────

    def _check_crontab_script_permissions(self) -> List[Finding]:
        """Parse all cron files and check if referenced scripts are world-writable."""
        script_paths = self._extract_script_paths()
        world_writable: List[str] = []
        writable_parent: List[str] = []

        for script in script_paths:
            p = Path(script)
            if not p.exists():
                continue
            # Check the script itself
            mode = p.stat().st_mode & 0o777
            if mode & 0o002:
                world_writable.append(f"{script}: {oct(mode)}")
            # Check the parent directory
            parent_mode = p.parent.stat().st_mode & 0o777
            if parent_mode & 0o002:
                writable_parent.append(f"{script} (parent {p.parent}: {oct(parent_mode)})")

        findings: List[Finding] = []
        if world_writable:
            findings.append(Finding(
                title="Cron scripts are world-writable",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(world_writable)} script(s) called by cron are world-writable. "
                    f"Any local user can overwrite these scripts to execute arbitrary "
                    f"commands with the privileges of the cron job owner (often root)."
                ),
                evidence="\n".join(world_writable),
                remediation=(
                    "Remove world-write permission: `chmod o-w <script>`. "
                    "Cron scripts should be owned by root and have mode 700 or 750."
                ),
                cis_refs=["CIS Linux 5.1"],
                module=self.module_name,
                check_id="cron-002",
            ))
        if writable_parent:
            findings.append(Finding(
                title="Cron scripts in world-writable directories",
                severity=Severity.HIGH,
                description=(
                    f"{len(writable_parent)} cron script(s) reside in world-writable "
                    f"directories. An attacker can place a malicious script in the same "
                    f"directory to replace or shadow the intended binary."
                ),
                evidence="\n".join(writable_parent),
                remediation=(
                    "Move cron scripts to root-owned, non-world-writable directories "
                    "(e.g. /usr/local/sbin/). Remove world-write from parent dirs."
                ),
                module=self.module_name,
                check_id="cron-003",
            ))
        if self.logger:
            self.logger.info(
                f"[{self.module_name}] script permission check: "
                f"{len(world_writable)} world-writable, {len(writable_parent)} in writable dirs"
            )
        return findings

    # ── Root cron entries with unsafe paths ───────────────────────────────────

    def _check_root_cron_paths(self) -> List[Finding]:
        """Flag root cron entries that call commands without absolute paths,
        or call from PATH locations that include user-writable dirs."""
        suspicious: List[str] = []
        all_entries = self._get_all_cron_entries()

        for source, user, command in all_entries:
            if user not in ("root", "0"):
                continue
            # Extract command tokens that look like executables (not env vars or flags)
            tokens = command.split()
            for token in tokens:
                if token.startswith("-") or "=" in token:
                    continue
                # Flag bare (non-absolute) command names
                if token and not token.startswith("/") and not token.startswith("("):
                    suspicious.append(
                        f"{source} [root]: '{command}' — bare command '{token}'"
                    )
                    break

        if suspicious:
            return [Finding(
                title="Root cron entries with non-absolute command paths",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(suspicious)} root cron entries use bare (non-absolute) "
                    f"command paths. If PATH is manipulated or a writable directory "
                    f"appears early in PATH, a malicious binary could be executed as root."
                ),
                evidence="\n".join(suspicious[:20]),
                remediation=(
                    "Use full absolute paths for all commands in root cron entries "
                    "(e.g. /usr/bin/find instead of find). "
                    "Set PATH explicitly at the top of crontab."
                ),
                cis_refs=["CIS Linux 5.1"],
                module=self.module_name,
                check_id="cron-004",
            )]
        return []

    # ── Cron access control ───────────────────────────────────────────────────

    def _check_cron_access_control(self) -> List[Finding]:
        allow = Path("/etc/cron.allow")
        deny  = Path("/etc/cron.deny")
        findings: List[Finding] = []

        if not allow.exists() and not deny.exists():
            findings.append(Finding(
                title="No cron access control configured",
                severity=Severity.MEDIUM,
                description=(
                    "Neither /etc/cron.allow nor /etc/cron.deny exists. "
                    "All users can schedule cron jobs. This should be restricted "
                    "to authorised accounts only."
                ),
                remediation=(
                    "Create /etc/cron.allow containing only the usernames that "
                    "should be permitted to use crontab. "
                    "When cron.allow exists, all other users are implicitly denied."
                ),
                cis_refs=["CIS Linux 5.1.8"],
                module=self.module_name,
                check_id="cron-005",
            ))

        if deny.exists():
            content = _read(str(deny))
            if "ALL" not in content.upper():
                findings.append(Finding(
                    title="/etc/cron.deny does not contain ALL",
                    severity=Severity.LOW,
                    description=(
                        "/etc/cron.deny exists but does not contain 'ALL'. "
                        "Users not explicitly listed can still schedule cron jobs. "
                        "Prefer /etc/cron.allow (allowlist) over /etc/cron.deny (denylist)."
                    ),
                    evidence=f"/etc/cron.deny contents:\n{content[:200]}",
                    remediation=(
                        "Switch to allowlist model: create /etc/cron.allow with "
                        "permitted users, remove /etc/cron.deny."
                    ),
                    cis_refs=["CIS Linux 5.1.8"],
                    module=self.module_name,
                    check_id="cron-005",
                ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] cron access control checked")
        return findings

    # ── at access control ────────────────────────────────────────────────────

    def _check_at_access_control(self) -> List[Finding]:
        at_allow = Path("/etc/at.allow")
        at_deny  = Path("/etc/at.deny")

        if not at_allow.exists() and not at_deny.exists():
            return [Finding(
                title="No at/batch access control configured",
                severity=Severity.LOW,
                description=(
                    "Neither /etc/at.allow nor /etc/at.deny exists. "
                    "All users may be able to schedule one-time jobs with `at`."
                ),
                remediation=(
                    "Create /etc/at.allow with authorised users only, "
                    "or create /etc/at.deny containing 'ALL'."
                ),
                cis_refs=["CIS Linux 5.1.9"],
                module=self.module_name,
                check_id="cron-006",
            )]
        return []

    # ── User crontabs ─────────────────────────────────────────────────────────

    def _check_user_crontabs(self) -> List[Finding]:
        """Enumerate user crontabs in /var/spool/cron/ for suspicious patterns."""
        spool_dirs = ["/var/spool/cron/crontabs", "/var/spool/cron"]
        findings: List[Finding] = []

        SUSPICIOUS_PATTERNS = [
            (r"curl\s+.*\|\s*(ba)?sh",   "pipe curl to shell"),
            (r"wget\s+.*\|\s*(ba)?sh",   "pipe wget to shell"),
            (r"base64\s+-d",             "base64 decode (potential obfuscation)"),
            (r"/tmp/\S+",                "execution from /tmp"),
            (r"nc\s+-",                  "netcat usage"),
            (r"python.*-c\s+['\"]",      "inline Python execution"),
            (r"bash\s+-i",               "interactive bash (reverse shell pattern)"),
        ]

        hits: List[str] = []
        for spool in spool_dirs:
            d = Path(spool)
            if not d.exists():
                continue
            for ctab in d.iterdir():
                if not ctab.is_file():
                    continue
                content = _read(str(ctab))
                for line in content.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    for pattern, label in SUSPICIOUS_PATTERNS:
                        if re.search(pattern, stripped, re.IGNORECASE):
                            hits.append(f"{ctab.name}: [{label}] {stripped[:120]}")

        if hits:
            findings.append(Finding(
                title="Suspicious patterns in user crontabs",
                severity=Severity.HIGH,
                description=(
                    f"{len(hits)} crontab entries match suspicious patterns "
                    f"(remote code execution, /tmp execution, obfuscation). "
                    f"These may indicate persistence mechanisms left by an attacker."
                ),
                evidence="\n".join(hits[:25]),
                remediation=(
                    "Review each flagged entry manually. Remove any cron entries "
                    "not authorised by the system owner."
                ),
                module=self.module_name,
                check_id="cron-007",
            ))

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] user crontab scan: {len(hits)} suspicious entries"
            )
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_script_paths(self) -> List[str]:
        """Extract filesystem paths referenced in cron entries."""
        paths: List[str] = []
        for source, user, command in self._get_all_cron_entries():
            for token in command.split():
                if token.startswith("/") and "." not in Path(token).suffix or \
                        token.startswith("/usr/") or token.startswith("/opt/"):
                    paths.append(token)
        return list(set(paths))

    def _get_all_cron_entries(self) -> List[Tuple[str, str, str]]:
        """
        Return (source_file, user, command) for every active cron entry
        in /etc/crontab and all files under SYSTEM_CRON_DIRS.

        /etc/crontab format:  min hr dom mon dow USER command
        /etc/cron.d/* format: same as crontab
        /etc/cron.daily/* etc: plain scripts (no schedule syntax), executed as root
        """
        entries: List[Tuple[str, str, str]] = []

        # System crontab and /etc/cron.d entries (have user field)
        for source in [SYSTEM_CRONTAB] + [
            str(f)
            for d in ["/etc/cron.d"]
            for f in (Path(d).iterdir() if Path(d).exists() else [])
            if f.is_file()
        ]:
            content = _read(source)
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("@"):
                    continue
                if "=" in stripped and len(stripped.split()) == 1:
                    continue  # env var definition
                parts = stripped.split()
                if len(parts) >= 7:
                    user = parts[5]
                    command = " ".join(parts[6:])
                    entries.append((source, user, command))

        # /etc/cron.{daily,hourly,weekly,monthly} — these run as root via run-parts
        for dir_path in SYSTEM_CRON_DIRS[1:]:
            d = Path(dir_path)
            if not d.exists():
                continue
            for script in d.iterdir():
                if script.is_file():
                    entries.append((str(script), "root", str(script)))

        return entries
