"""Module 2: Authentication, Access Control & Privilege Management."""
from __future__ import annotations
import stat
import re
import os
import subprocess
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity

try:
    import pwd as _pwd
    _HAS_PWD = True
except ImportError:
    _HAS_PWD = False


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


class AuthChecker(Checker):
    module_name = "auth_privilege"

    def list_checks(self) -> List[str]:
        return [
            "Check sudoers for NOPASSWD / wildcard misconfigurations",
            "Inventory SUID/SGID binaries",
            "Check SSH daemon hardening (root login, password auth, ciphers)",
            "Check password policy (login.defs) — PASS_MAX_DAYS & PASS_MIN_LEN",
            "Check for accounts with empty passwords / UID 0 duplicates",
            "Audit file capabilities (getcap)",
            "Check PAM configuration (lockout policy, password complexity, nullok, MFA)",
            "Audit SSH authorized_keys across all home directories",
            "Audit PATH environment variable for relative or world-writable directories",
            "Scan shell history files for hardcoded secrets",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_sudoers()
        findings += self._check_suid_sgid()
        findings += self._check_ssh_config()
        findings += self._check_password_policy()
        findings += self._check_accounts()
        findings += self._check_file_capabilities()
        findings += self._check_pam_config()
        findings += self._check_ssh_authorized_keys()
        findings += self._check_path_environment()
        findings += self._check_history_files()
        return findings

    def _check_sudoers(self) -> List[Finding]:
        findings = []
        sources = ["/etc/sudoers"]
        sudoers_d = Path("/etc/sudoers.d")
        if sudoers_d.exists():
            sources += [str(p) for p in sudoers_d.glob("*") if p.is_file()]

        nopasswd_hits: List[str] = []
        wildcard_hits: List[str] = []
        env_keep_hits: List[str] = []
        dangerous_sudo_hits: List[str] = []
        
        GTFOBINS = {
            "find", "vim", "vi", "nano", "bash", "sh", "python", "python3", "perl",
            "awk", "less", "more", "cp", "mv", "dd", "tar", "zip", "unzip",
            "systemctl", "journalctl", "socat", "nc", "nmap", "git", "docker",
            "env", "nethack", "base64", "gdb", "ruby", "php", "screen", "tmux",
            "strace", "curl", "wget", "nice", "time", "date", "whois", "scp",
            "sftp", "ftp", "tftp", "telnet", "ash", "dash", "zsh", "awk", "sed",
            "tee", "pkexec", "taskset", "flock", "xargs", "micro", "emacs"
        }

        for src in sources:
            file_content = _read(src)
            for line in file_content.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                if "NOPASSWD" in stripped:
                    nopasswd_hits.append(f"{src}: {stripped}")
                    
                # Flag group wildcards with full ALL=(ALL:ALL) ALL
                if re.search(r"^%\S+\s+ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", stripped):
                    wildcard_hits.append(f"{src}: {stripped}")
                
                # Check for env_keep variables
                if "env_keep" in stripped:
                    for var in ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "RUBYOPT"]:
                        if var in stripped:
                            env_keep_hits.append(f"{src}: {stripped}")
                            break
                            
                # Check for dangerous binaries allowed in sudoers
                # Format: user host = (runas) COMMAND
                # Parse commands
                parts = re.split(r'=\s*', stripped, 1)
                if len(parts) > 1:
                    cmds_part = parts[1]
                    for binary in GTFOBINS:
                        # Matches command endings or paths, e.g. /usr/bin/find or find
                        if re.search(rf"(?:^|[\s,:/]){binary}(?:\s|,|$)", cmds_part):
                            dangerous_sudo_hits.append(f"{src}: {stripped}")
                            break

        if nopasswd_hits:
            findings.append(Finding(
                title="NOPASSWD sudo rules present",
                severity=Severity.MEDIUM,
                description=(
                    "One or more sudoers entries grant command execution without a "
                    "password prompt. If scoped too broadly this is a direct path to "
                    "root for anyone who compromises the account."
                ),
                evidence="\n".join(nopasswd_hits[:10]),
                remediation=(
                    "Scope NOPASSWD to the minimum specific commands required; "
                    "never use NOPASSWD with ALL."
                ),
                cis_refs=["CIS Linux 5.3"],
                module=self.module_name,
                check_id="auth-001",
            ))

        if env_keep_hits:
            findings.append(Finding(
                title="Dangerous env_keep configured in sudoers",
                severity=Severity.CRITICAL,
                description=(
                    "Sudoers configuration retains dangerous environment variables "
                    "(e.g., LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH) during execution. "
                    "An unprivileged user can hijack library loading on sudo-accessible "
                    "binaries to gain immediate root privileges."
                ),
                evidence="\n".join(env_keep_hits),
                remediation=(
                    "Remove dangerous environment variables from env_keep configurations. "
                    "Enforce env_reset (default behaviour)."
                ),
                cis_refs=["CIS Linux 5.3"],
                module=self.module_name,
                check_id="auth-017",
            ))

        if dangerous_sudo_hits:
            findings.append(Finding(
                title="Dangerous commands allowed in sudoers",
                severity=Severity.HIGH,
                description=(
                    "Sudoers config allows execution of command-line utilities "
                    "known to have shell escape features (GTFOBins). If users can run "
                    "these via sudo, they can easily spawn a root shell or read/write "
                    "arbitrary system files."
                ),
                evidence="\n".join(dangerous_sudo_hits[:15]),
                remediation=(
                    "Avoid granting sudo access to binaries with built-in shell escape "
                    "capabilities. Use restricted wrappers or strictly scoped sudo configurations."
                ),
                cis_refs=["CIS Linux 5.3"],
                module=self.module_name,
                check_id="auth-018",
            ))

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] sudoers scanned: {len(sources)} files"
            )
        return findings

    def _check_suid_sgid(self) -> List[Finding]:
        # Known-safe baseline of common, expected SUID/SGID binaries (distro defaults).
        KNOWN_SAFE = {
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount",
            "/usr/bin/umount", "/usr/bin/ping", "/usr/bin/fusermount",
            "/usr/lib/openssh/ssh-keysign", "/usr/bin/pkexec", "/usr/bin/at",
            "/usr/bin/crontab", "/usr/sbin/unix_chkpwd",
        }
        out = _run(
            ["find", "/", "-xdev", "-type", "f",
             "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"],
            timeout=120,
        )
        binaries = [b for b in out.strip().splitlines() if b]
        unexpected = [b for b in binaries if b not in KNOWN_SAFE]

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] found {len(binaries)} SUID/SGID binaries, "
                f"{len(unexpected)} outside known-safe baseline"
            )

        findings = [Finding(
            title="SUID/SGID binary inventory",
            severity=Severity.INFO,
            description=f"{len(binaries)} SUID/SGID binaries found on the filesystem.",
            evidence="\n".join(binaries[:50]),
            module=self.module_name,
            check_id="auth-002",
        )]
        if unexpected:
            findings.append(Finding(
                title="SUID/SGID binaries outside known-safe baseline",
                severity=Severity.MEDIUM,
                description=(
                    "These binaries carry the setuid/setgid bit but aren't in the "
                    "common distro baseline. Review each for legitimate need; unused "
                    "SUID binaries are a classic local privilege escalation vector. "
                    "Cross-check against GTFOBins."
                ),
                evidence="\n".join(unexpected[:50]),
                remediation=(
                    "Remove the setuid/setgid bit (chmod -s) on binaries that don't "
                    "need it, or uninstall unused software providing them."
                ),
                cis_refs=["CIS Linux 6.1.13"],
                module=self.module_name,
                check_id="auth-003",
            ))
        return findings

    def _check_ssh_config(self) -> List[Finding]:
        content = _read("/etc/ssh/sshd_config")
        if not content:
            return []
        findings = []

        def get_directive(name: str, default: str = "") -> str:
            m = re.search(rf"^\s*{name}\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
            return m.group(1) if m else default

        root_login = get_directive("PermitRootLogin", "prohibit-password")
        if root_login.lower() == "yes":
            findings.append(Finding(
                title="SSH PermitRootLogin enabled",
                severity=Severity.HIGH,
                description=(
                    "sshd_config allows direct root login over SSH, removing the "
                    "audit trail of which admin account was used and widening the "
                    "blast radius of a single leaked credential."
                ),
                evidence=f"PermitRootLogin {root_login}",
                remediation=(
                    "Set 'PermitRootLogin no' (or 'prohibit-password' at minimum) "
                    "and require sudo from a named account instead."
                ),
                cis_refs=["CIS Linux 5.2.10"],
                module=self.module_name,
                check_id="auth-004",
            ))

        pw_auth = get_directive("PasswordAuthentication", "yes")
        if pw_auth.lower() == "yes":
            findings.append(Finding(
                title="SSH password authentication enabled",
                severity=Severity.MEDIUM,
                description=(
                    "Password authentication over SSH is enabled, leaving the service "
                    "exposed to credential brute-forcing. Key-based auth is materially stronger."
                ),
                evidence=f"PasswordAuthentication {pw_auth}",
                remediation="Set 'PasswordAuthentication no' and enforce public-key auth.",
                cis_refs=["CIS Linux 5.2.11"],
                module=self.module_name,
                check_id="auth-005",
            ))

        empty_pw = get_directive("PermitEmptyPasswords", "no")
        if empty_pw.lower() == "yes":
            findings.append(Finding(
                title="SSH PermitEmptyPasswords enabled",
                severity=Severity.CRITICAL,
                description="sshd_config explicitly permits login with an empty password.",
                evidence=f"PermitEmptyPasswords {empty_pw}",
                remediation="Set 'PermitEmptyPasswords no'.",
                cis_refs=["CIS Linux 5.2.12"],
                module=self.module_name,
                check_id="auth-006",
            ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] sshd_config checked")
        return findings

    def _check_password_policy(self) -> List[Finding]:
        content = _read("/etc/login.defs")
        if not content:
            return []
        findings = []

        def get_int(name: str):
            m = re.search(rf"^\s*{name}\s+(\d+)", content, re.MULTILINE)
            return int(m.group(1)) if m else None

        max_days = get_int("PASS_MAX_DAYS")
        min_len = get_int("PASS_MIN_LEN")

        if max_days is not None and (max_days == 0 or max_days > 365):
            findings.append(Finding(
                title="Weak password expiry policy (PASS_MAX_DAYS)",
                severity=Severity.LOW,
                description=(
                    f"PASS_MAX_DAYS={max_days} in /etc/login.defs is unset or too long, "
                    f"meaning compromised passwords may remain valid indefinitely."
                ),
                evidence=f"PASS_MAX_DAYS {max_days}",
                remediation="Set PASS_MAX_DAYS to 90 or less per organizational policy.",
                cis_refs=["CIS Linux 5.4.1.1"],
                module=self.module_name,
                check_id="auth-007",
            ))

        # Flag explicitly if minimum length is shorter than 8 characters
        if min_len is not None and min_len < 8:
            findings.append(Finding(
                title="Weak minimum password length (PASS_MIN_LEN)",
                severity=Severity.MEDIUM,
                description=(
                    f"PASS_MIN_LEN={min_len} in /etc/login.defs allows passwords shorter "
                    f"than 8 characters, making brute-force attacks trivially fast."
                ),
                evidence=f"PASS_MIN_LEN {min_len}",
                remediation="Set PASS_MIN_LEN to at least 12 in /etc/login.defs.",
                cis_refs=["CIS Linux 5.4.1.4"],
                module=self.module_name,
                check_id="auth-007b",
            ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] login.defs checked")
        return findings

    def _check_accounts(self) -> List[Finding]:
        findings = []
        if not _HAS_PWD:
            return []

        import pwd
        uid0_users = [p.pw_name for p in pwd.getpwall() if p.pw_uid == 0]
        if len(uid0_users) > 1:
            findings.append(Finding(
                title="Multiple UID 0 (root-equivalent) accounts",
                severity=Severity.CRITICAL,
                description=(
                    "More than one account shares UID 0, meaning multiple usernames "
                    "have full root privileges — a common backdoor technique and an "
                    "audit-trail nightmare."
                ),
                evidence=", ".join(uid0_users),
                remediation="Investigate immediately; only 'root' should have UID 0.",
                cis_refs=["CIS Linux 6.2.9"],
                module=self.module_name,
                check_id="auth-008",
            ))

        shadow = _read("/etc/shadow")
        empty_pw_accounts = []
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) > 1 and parts[1] == "":
                empty_pw_accounts.append(parts[0])
        if empty_pw_accounts:
            findings.append(Finding(
                title="Accounts with empty passwords",
                severity=Severity.CRITICAL,
                description="One or more local accounts have no password set in /etc/shadow.",
                evidence=", ".join(empty_pw_accounts),
                remediation="Lock or set passwords on these accounts immediately (passwd -l).",
                cis_refs=["CIS Linux 6.2.1"],
                module=self.module_name,
                check_id="auth-009",
            ))
        if self.logger:
            self.logger.info(f"[{self.module_name}] account inventory checked")
        return findings

    def _check_file_capabilities(self) -> List[Finding]:
        """Check for extended file capabilities that can substitute for SUID."""
        out = _run(["getcap", "-r", "/"], timeout=120)
        if not out.strip():
            return []

        HIGH_RISK_CAPS = {
            "cap_net_admin", "cap_sys_admin", "cap_sys_ptrace",
            "cap_dac_override", "cap_dac_read_search", "cap_setuid",
            "cap_setgid", "cap_sys_rawio",
        }
        risky = []
        for line in out.strip().splitlines():
            lower = line.lower()
            if any(cap in lower for cap in HIGH_RISK_CAPS):
                risky.append(line)

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] getcap found {len(out.splitlines())} capabilities; "
                f"{len(risky)} high-risk"
            )

        findings = [Finding(
            title="File capabilities inventory",
            severity=Severity.INFO,
            description=f"File capabilities found on filesystem (getcap -r /).",
            evidence=out[:3000],
            module=self.module_name,
            check_id="auth-010",
        )]
        if risky:
            findings.append(Finding(
                title="High-risk file capabilities detected",
                severity=Severity.HIGH,
                description=(
                    "One or more binaries have high-privilege Linux capabilities set "
                    "(e.g. cap_sys_admin, cap_dac_override). These can be as dangerous "
                    "as SUID root and are a common privilege escalation vector."
                ),
                evidence="\n".join(risky),
                remediation=(
                    "Remove unnecessary capabilities with: `setcap -r <binary>`. "
                    "Only grant the minimum capability required."
                ),
                cis_refs=["CIS Linux 6.1.14"],
                module=self.module_name,
                check_id="auth-011",
            ))
        return findings

    def _check_pam_config(self) -> list:
        import glob, re
        findings = []
        pam_files = (
            glob.glob('/etc/pam.d/common-*') +
            glob.glob('/etc/pam.d/system-auth*') +
            glob.glob('/etc/pam.d/password-auth*') +
            ['/etc/pam.d/login', '/etc/pam.d/sshd', '/etc/pam.d/sudo']
        )
        from pathlib import Path
        from core.models import Finding, Severity
        all_pam = ''
        for pf in pam_files:
            try:
                all_pam += Path(pf).read_text(encoding='utf-8')
            except Exception:
                pass
        if not all_pam.strip():
            return []
        has_faillock = 'pam_faillock' in all_pam
        has_tally2 = 'pam_tally2' in all_pam
        if not has_faillock and not has_tally2:
            findings.append(Finding(title='No PAM account lockout policy configured',severity=Severity.HIGH,description='Neither pam_faillock nor pam_tally2 is configured. Online brute-force against local accounts (su, login, sudo) is unrestricted.',remediation='Configure pam_faillock in /etc/pam.d/common-auth: auth required pam_faillock.so preauth silent deny=5 unlock_time=900',cis_refs=['CIS Linux 5.4.2'],module=self.module_name,check_id='auth-012'))
        else:
            m = re.search(r'pam_faillock\.so.*deny=(\d+)', all_pam)
            if m and int(m.group(1)) > 5:
                findings.append(Finding(title=f'PAM lockout threshold too high (deny={m.group(1)})',severity=Severity.MEDIUM,description=f'pam_faillock deny={m.group(1)} allows too many attempts. Recommended: 3-5.',evidence=f'deny={m.group(1)}',remediation='Set deny=5 or lower.',cis_refs=['CIS Linux 5.4.2'],module=self.module_name,check_id='auth-012'))
        has_pwquality = 'pam_pwquality' in all_pam
        has_cracklib = 'pam_cracklib' in all_pam
        if not has_pwquality and not has_cracklib:
            findings.append(Finding(title='No PAM password complexity enforcement',severity=Severity.MEDIUM,description='Neither pam_pwquality nor pam_cracklib configured. Users can set weak passwords.',remediation='Add: password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1',cis_refs=['CIS Linux 5.4.1'],module=self.module_name,check_id='auth-013'))
        else:
            m = re.search(r'minlen=(\d+)', all_pam)
            if m and int(m.group(1)) < 12:
                findings.append(Finding(title=f'PAM password minlen too short ({m.group(1)} chars)',severity=Severity.MEDIUM,description=f'minlen={m.group(1)} is below recommended 12.',evidence=f'minlen={m.group(1)}',remediation='Set minlen=12 or higher.',cis_refs=['CIS Linux 5.4.1.4'],module=self.module_name,check_id='auth-013'))
        nullok_lines = [ln for ln in all_pam.splitlines() if 'nullok' in ln and not ln.strip().startswith('#')]
        if nullok_lines:
            findings.append(Finding(title='PAM nullok allows empty password logins',severity=Severity.HIGH,description='PAM nullok permits accounts with empty passwords to authenticate.',evidence='\n'.join(nullok_lines[:5]),remediation='Remove nullok from all PAM auth lines. Lock passwordless accounts: passwd -l <user>.',cis_refs=['CIS Linux 5.4.1'],module=self.module_name,check_id='auth-014'))
        mfa_mods = ['pam_google_authenticator','pam_duo','pam_oath','pam_radius','pam_u2f','pam_yubikey']
        has_mfa = any(m in all_pam for m in mfa_mods)
        findings.append(Finding(title='MFA configured via PAM' if has_mfa else 'No MFA detected in PAM',severity=Severity.INFO if has_mfa else Severity.LOW,description='MFA module detected in PAM.' if has_mfa else 'No MFA PAM module detected. MFA significantly reduces impact of credential theft.',remediation='' if has_mfa else 'Deploy pam_duo, pam_google_authenticator, or pam_u2f.',module=self.module_name,check_id='auth-015'))
        if self.logger:
            self.logger.info(f'[{self.module_name}] PAM configuration checked')
        return findings

    def _check_history_files(self) -> List[Finding]:
        import glob
        import re
        findings = []
        history_files = glob.glob("/root/.*_history") + glob.glob("/home/*/.*_history")
        
        # Patterns indicative of secrets passed via CLI
        patterns = [
            (r"-p\s*['\"]?\S+['\"]?", "Password flag"),
            (r"password\s*=\s*['\"]?\S+['\"]?", "Password assignment"),
            (r"AWS_ACCESS_KEY_ID\s*=\s*['\"]?\S+['\"]?", "AWS Access Key"),
            (r"token\s*=\s*['\"]?\S+['\"]?", "Token assignment")
        ]
        
        hits = []
        for hf in history_files:
            content = _read(hf)
            if not content:
                continue
            for line in content.splitlines():
                for pat, desc in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        hits.append(f"{hf}: [Matches {desc}] {line.strip()[:100]}")
                        
        if hits:
            findings.append(Finding(
                title="Secrets found in shell history files",
                severity=Severity.HIGH,
                description=(
                    "Shell history files (.bash_history, .mysql_history, etc.) contain "
                    "commands that appear to include hardcoded passwords, tokens, or keys. "
                    "If an attacker reads these files, they can trivially escalate privileges "
                    "or pivot to other systems."
                ),
                evidence="\n".join(hits[:20]),
                remediation="Clear the affected history files and avoid passing secrets via CLI arguments. Use environment variables or config files.",
                module=self.module_name,
                check_id="auth-021",
            ))
        return findings

    def _check_ssh_authorized_keys(self) -> List[Finding]:
        findings = []
        out = _run(["find", "/", "-name", "authorized_keys", "-type", "f", "-perm", "-0002", "2>/dev/null"])
        if out and out.strip():
            files = out.strip().splitlines()
            findings.append(Finding(
                title="World-writable SSH authorized_keys",
                severity=Severity.CRITICAL,
                description="SSH authorized_keys files were found to be world-writable. Any user can add their own SSH key and log in as the victim user (potentially root).",
                evidence="\n".join(files),
                remediation="Run: chmod 600 ~/.ssh/authorized_keys",
                module=self.module_name,
                check_id="auth-022"
            ))
        return findings

    def _check_path_environment(self) -> List[Finding]:
        findings = []
        path_var = _run(["printenv", "PATH"]).strip()
        if not path_var:
            return []
            
        paths = path_var.split(':')
        vulnerable_paths = []
        for p in paths:
            if p == "" or p == "." or not p.startswith("/"):
                vulnerable_paths.append(f"Relative path found: '{p}'")
            elif Path(p).exists():
                try:
                    if os.stat(p).st_mode & 0o002:
                        vulnerable_paths.append(f"World-writable path found: '{p}'")
                except OSError:
                    pass
                    
        if vulnerable_paths:
            findings.append(Finding(
                title="Insecure PATH environment variable",
                severity=Severity.HIGH,
                description="The PATH environment variable contains relative or world-writable directories. This allows local privilege escalation via PATH hijacking if a privileged user or script executes a command without an absolute path.",
                evidence="\n".join(vulnerable_paths),
                remediation="Remove relative and world-writable directories from PATH.",
                module=self.module_name,
                check_id="auth-023"
            ))
        return findings
