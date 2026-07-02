"""Module 9: Cryptographic Implementation.

Checks:
  - TLS configuration (OpenSSL defaults, weak protocol versions)
  - SSH daemon cipher / MAC / KEX strength
  - SSH host key size (RSA < 3072, DSA presence)
  - System entropy health (/proc/sys/kernel/random/entropy_avail)
  - OpenSSL version inventory
  - Hardcoded credential patterns in common config locations
"""
from __future__ import annotations
import subprocess
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
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _run_stderr(cmd: List[str], timeout: int = 10) -> str:
    """Capture stderr (some tools output to stderr by default)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        )
        return r.stdout + r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


class CryptoChecker(Checker):
    module_name = "crypto_implementation"

    def list_checks(self) -> List[str]:
        return [
            "Audit OpenSSL version (inventory for CVE cross-check)",
            "Check TLS configuration in /etc/ssl/openssl.cnf (weak protocols)",
            "Check SSH cipher / MAC / KEX strength in sshd_config",
            "Check SSH host key sizes (RSA < 3072, DSA = always flag)",
            "Check system entropy health (/proc/sys/kernel/random/entropy_avail)",
            "Scan common config files for hardcoded credential patterns",
            "Check SSH client configuration for StrictHostKeyChecking",
            "Scan for unprotected private SSH keys",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_openssl_version()
        findings += self._check_tls_config()
        findings += self._check_ssh_ciphers()
        findings += self._check_ssh_host_keys()
        findings += self._check_entropy()
        findings += self._check_hardcoded_creds()
        findings += self._check_ssh_client_config()
        findings += self._check_private_ssh_keys()
        return findings

    # ── OpenSSL version ───────────────────────────────────────────────────────

    def _check_openssl_version(self) -> List[Finding]:
        out = _run(["openssl", "version", "-a"])
        if not out.strip():
            return [Finding(
                title="OpenSSL not found",
                severity=Severity.INFO,
                description="openssl binary not found in PATH.",
                module=self.module_name,
                check_id="crypto-001",
            )]

        version_line = out.splitlines()[0] if out else ""
        if self.logger:
            self.logger.info(f"[{self.module_name}] OpenSSL version: {version_line}")

        # Flag known EOL/CVE-heavy releases
        EOL_PATTERNS = [
            r"OpenSSL 1\.0\.",   # EOL Jan 2020
            r"OpenSSL 1\.1\.0",  # EOL Sep 2019
        ]
        for pattern in EOL_PATTERNS:
            if re.search(pattern, version_line):
                return [Finding(
                    title="EOL OpenSSL version detected",
                    severity=Severity.HIGH,
                    description=(
                        f"The installed OpenSSL version ({version_line.strip()}) is "
                        f"end-of-life and no longer receives security patches. "
                        f"Multiple critical CVEs exist against this version."
                    ),
                    evidence=version_line.strip(),
                    remediation=(
                        "Upgrade to OpenSSL 3.x (currently supported). "
                        "Use your distro's package manager: `apt-get upgrade openssl`."
                    ),
                    cve_refs=["CVE-2022-0778", "CVE-2021-3711", "CVE-2020-1967"],
                    module=self.module_name,
                    check_id="crypto-001",
                )]

        return [Finding(
            title="OpenSSL version inventory",
            severity=Severity.INFO,
            description=(
                f"Installed: {version_line.strip()}. "
                f"Cross-check against NVD for any recent CVEs."
            ),
            evidence=out.strip(),
            module=self.module_name,
            check_id="crypto-001",
        )]

    # ── TLS configuration ─────────────────────────────────────────────────────

    def _check_tls_config(self) -> List[Finding]:
        content = _read("/etc/ssl/openssl.cnf")
        if not content:
            return []
        findings = []

        WEAK_PROTOCOLS = {
            "SSLv2": ("SSLv2 enabled in openssl.cnf",  Severity.CRITICAL,
                      "SSLv2 is completely broken (DROWN attack). Remove from config."),
            "SSLv3": ("SSLv3 enabled in openssl.cnf",  Severity.CRITICAL,
                      "SSLv3 is broken (POODLE). Remove from config."),
            "TLSv1\\.0|TLSv1 ": ("TLS 1.0 may be enabled", Severity.HIGH,
                      "TLS 1.0 is deprecated (PCI-DSS 3.2+). Set MinProtocol = TLSv1.2."),
            "TLSv1\\.1": ("TLS 1.1 may be enabled", Severity.MEDIUM,
                      "TLS 1.1 is deprecated. Set MinProtocol = TLSv1.2."),
        }
        for pattern, (title, sev, rem) in WEAK_PROTOCOLS.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    title=title,
                    severity=sev,
                    description=(
                        f"openssl.cnf references {pattern.replace('|.*', '')} which "
                        f"may allow weak TLS negotiation."
                    ),
                    evidence=f"/etc/ssl/openssl.cnf: pattern '{pattern}' found",
                    remediation=rem,
                    cis_refs=["CIS Linux 3.4"],
                    module=self.module_name,
                    check_id="crypto-002",
                ))

        # Check MinProtocol directive
        m = re.search(r"MinProtocol\s*=\s*(\S+)", content, re.IGNORECASE)
        if m:
            min_proto = m.group(1)
            if min_proto.lower() in ("sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"):
                findings.append(Finding(
                    title=f"MinProtocol set to weak value: {min_proto}",
                    severity=Severity.HIGH,
                    description=(
                        f"openssl.cnf sets MinProtocol = {min_proto}, permitting "
                        f"weak TLS connections system-wide."
                    ),
                    evidence=f"MinProtocol = {min_proto}",
                    remediation="Set MinProtocol = TLSv1.2 (or TLSv1.3 for maximum security).",
                    module=self.module_name,
                    check_id="crypto-002",
                ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] TLS config checked")
        return findings

    # ── SSH cipher / MAC / KEX strength ──────────────────────────────────────

    def _check_ssh_ciphers(self) -> List[Finding]:
        content = _read("/etc/ssh/sshd_config")
        if not content:
            return []
        findings = []

        WEAK_CIPHERS = [
            "3des-cbc", "arcfour", "arcfour128", "arcfour256",
            "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
        ]
        WEAK_MACS = [
            "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
            "umac-64", "hmac-ripemd160",
        ]
        WEAK_KEX = [
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
        ]

        def get_directive(name: str) -> str:
            m = re.search(rf"^\s*{name}\s+(.+)", content, re.MULTILINE | re.IGNORECASE)
            return m.group(1).strip() if m else ""

        ciphers_line = get_directive("Ciphers")
        if ciphers_line:
            bad = [c for c in WEAK_CIPHERS if c in ciphers_line.lower()]
            if bad:
                findings.append(Finding(
                    title="Weak SSH ciphers configured",
                    severity=Severity.HIGH,
                    description=(
                        "sshd_config explicitly lists weak/deprecated ciphers. "
                        "These include CBC-mode ciphers vulnerable to BEAST and "
                        "RC4-based ciphers with known key biases."
                    ),
                    evidence=f"Ciphers: {ciphers_line}\nWeak entries: {', '.join(bad)}",
                    remediation=(
                        "Restrict to: chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,"
                        "aes256-gcm@openssh.com"
                    ),
                    cis_refs=["CIS Linux 5.2.13"],
                    module=self.module_name,
                    check_id="crypto-003",
                ))

        macs_line = get_directive("MACs")
        if macs_line:
            bad = [m for m in WEAK_MACS if m in macs_line.lower()]
            if bad:
                findings.append(Finding(
                    title="Weak SSH MACs configured",
                    severity=Severity.MEDIUM,
                    description=(
                        "sshd_config includes MD5 or SHA-1 based MACs. "
                        "These hash algorithms are deprecated for integrity verification."
                    ),
                    evidence=f"MACs: {macs_line}\nWeak entries: {', '.join(bad)}",
                    remediation=(
                        "Restrict to: hmac-sha2-512-etm@openssh.com,"
                        "hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
                    ),
                    cis_refs=["CIS Linux 5.2.14"],
                    module=self.module_name,
                    check_id="crypto-004",
                ))

        kex_line = get_directive("KexAlgorithms")
        if kex_line:
            bad = [k for k in WEAK_KEX if k in kex_line.lower()]
            if bad:
                findings.append(Finding(
                    title="Weak SSH key exchange algorithms configured",
                    severity=Severity.HIGH,
                    description=(
                        "sshd_config includes deprecated Diffie-Hellman group1/group14 "
                        "or SHA-1 based key exchange, vulnerable to Logjam-style attacks."
                    ),
                    evidence=f"KexAlgorithms: {kex_line}\nWeak entries: {', '.join(bad)}",
                    remediation=(
                        "Restrict to: curve25519-sha256,curve25519-sha256@libssh.org,"
                        "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
                    ),
                    cis_refs=["CIS Linux 5.2.15"],
                    module=self.module_name,
                    check_id="crypto-005",
                ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] SSH cipher/MAC/KEX checked")
        return findings

    # ── SSH host key sizes ────────────────────────────────────────────────────

    def _check_ssh_host_keys(self) -> List[Finding]:
        if not shutil.which("ssh-keygen"):
            return []
        findings = []
        ssh_dir = Path("/etc/ssh")
        if not ssh_dir.exists():
            return []
        for key in ssh_dir.glob("ssh_host_*_key"):
            out = _run_stderr(["ssh-keygen", "-l", "-f", str(key)])
            if not out.strip():
                continue
            # Output: "3072 SHA256:... root@host (RSA)"
            parts = out.strip().split()
            if len(parts) < 4:
                continue
            try:
                bits = int(parts[0])
            except ValueError:
                continue
            key_type = parts[-1].strip("()").upper()

            if key_type == "DSA":
                findings.append(Finding(
                    title=f"DSA host key present: {key.name}",
                    severity=Severity.HIGH,
                    description=(
                        "DSA keys are fixed at 1024 bits and cryptographically weak. "
                        "OpenSSH 7.0+ disables them by default for good reason."
                    ),
                    evidence=out.strip(),
                    remediation=(
                        "Remove the DSA host key and regenerate with Ed25519: "
                        "`ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key`"
                    ),
                    module=self.module_name,
                    check_id="crypto-006",
                ))
            elif key_type == "RSA" and bits < 3072:
                findings.append(Finding(
                    title=f"RSA host key too short: {bits} bits ({key.name})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"RSA host key is {bits} bits. NIST recommends >= 3072 bits "
                        f"(equivalent to 128-bit security) for RSA keys."
                    ),
                    evidence=out.strip(),
                    remediation=(
                        "Regenerate with a 4096-bit RSA key or migrate to Ed25519: "
                        "`ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key`"
                    ),
                    module=self.module_name,
                    check_id="crypto-006",
                ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] SSH host keys checked")
        return findings

    # ── Entropy health ────────────────────────────────────────────────────────

    def _check_entropy(self) -> List[Finding]:
        val_str = _read("/proc/sys/kernel/random/entropy_avail").strip()
        if not val_str:
            return []
        try:
            entropy = int(val_str)
        except ValueError:
            return []

        if entropy < 200:
            return [Finding(
                title=f"Critically low entropy pool: {entropy} bits",
                severity=Severity.HIGH,
                description=(
                    f"The kernel entropy pool has only {entropy} bits available. "
                    f"Cryptographic operations (key generation, TLS) that block on "
                    f"/dev/random may stall or fall back to predictable values."
                ),
                evidence=f"/proc/sys/kernel/random/entropy_avail = {entropy}",
                remediation=(
                    "Install haveged or rng-tools to supplement entropy: "
                    "`apt install haveged`. For VMs, enable virtio-rng."
                ),
                module=self.module_name,
                check_id="crypto-007",
            )]
        if entropy < 1000:
            return [Finding(
                title=f"Low entropy pool: {entropy} bits",
                severity=Severity.LOW,
                description=(
                    f"Entropy pool has {entropy} bits. Normal systems typically "
                    f"maintain >1000. This may indicate a VM with no hardware RNG."
                ),
                evidence=f"/proc/sys/kernel/random/entropy_avail = {entropy}",
                remediation="Install haveged or enable virtio-rng for the VM.",
                module=self.module_name,
                check_id="crypto-007",
            )]
        return [Finding(
            title=f"Entropy pool healthy: {entropy} bits",
            severity=Severity.INFO,
            description=f"Kernel entropy pool: {entropy} bits available.",
            module=self.module_name,
            check_id="crypto-007",
        )]

    # ── Hardcoded credentials ─────────────────────────────────────────────────

    def _check_hardcoded_creds(self) -> List[Finding]:
        """Grep common system config files for credential-like patterns."""
        SEARCH_DIRS = ["/etc", "/opt", "/srv", "/home"]
        # Patterns that strongly suggest hardcoded secrets
        PATTERNS = [
            r'(?i)password\s*=\s*["\']?[^\s"\'#]{4,}',
            r'(?i)passwd\s*=\s*["\']?[^\s"\'#]{4,}',
            r'(?i)secret\s*=\s*["\']?[^\s"\'#]{4,}',
            r'(?i)api_?key\s*=\s*["\']?[^\s"\'#]{8,}',
            r'(?i)token\s*=\s*["\']?[^\s"\'#]{8,}',
        ]
        hits: List[str] = []

        if not shutil.which("grep"):
            return []

        for search_dir in SEARCH_DIRS:
            if not Path(search_dir).exists():
                continue
            for pattern in PATTERNS:
                try:
                    result = subprocess.run(
                        ["grep", "-rn", "--include=*.conf", "--include=*.cfg",
                         "--include=*.ini", "--include=*.env",
                         "-E", pattern, search_dir],
                        capture_output=True, text=True, check=False, timeout=30,
                    )
                    for line in result.stdout.splitlines()[:5]:
                        # Redact the actual value for safe reporting
                        redacted = re.sub(
                            r'(=\s*["\']?)([^\s"\'#]{4,})',
                            r'\1[REDACTED]',
                            line
                        )
                        hits.append(redacted)
                except subprocess.TimeoutExpired:
                    continue

        if not hits:
            return []

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] hardcoded credential scan: {len(hits)} pattern hits"
            )

        return [Finding(
            title="Possible hardcoded credentials in config files",
            severity=Severity.HIGH,
            description=(
                f"{len(hits)} lines in config files match credential-like patterns "
                f"(password=, secret=, api_key=, token=). Values have been redacted "
                f"in this report; review the flagged files manually."
            ),
            evidence="\n".join(hits[:20]),
            remediation=(
                "Move secrets to a secrets manager, environment variables, or a "
                "vault (e.g. HashiCorp Vault, systemd credentials). Never store "
                "plaintext credentials in config files."
            ),
            module=self.module_name,
            check_id="crypto-008",
        )]

    def _check_ssh_client_config(self) -> List[Finding]:
        findings = []
        content = _read("/etc/ssh/ssh_config")
        if not content:
            return findings
            
        strict_host_key = "yes"
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("StrictHostKeyChecking"):
                parts = line.split()
                if len(parts) > 1:
                    strict_host_key = parts[1].lower()
                    
        if strict_host_key == "no":
            findings.append(Finding(
                title="SSH Client StrictHostKeyChecking disabled",
                severity=Severity.MEDIUM,
                description=(
                    "The system-wide SSH client configuration (/etc/ssh/ssh_config) has "
                    "StrictHostKeyChecking set to 'no'. This makes the client vulnerable "
                    "to Man-In-The-Middle (MITM) attacks when connecting to remote hosts."
                ),
                evidence="StrictHostKeyChecking no",
                remediation="Set StrictHostKeyChecking to 'ask' or 'yes' in /etc/ssh/ssh_config.",
                module=self.module_name,
                check_id="crypto-008",
            ))
        return findings

    def _check_private_ssh_keys(self) -> List[Finding]:
        findings = []
        out = _run(["find", "/", "-name", "id_rsa", "-o", "-name", "id_ed25519", "-type", "f", "-perm", "/077", "2>/dev/null"])
        if out and out.strip():
            keys = out.strip().splitlines()
            findings.append(Finding(
                title="Poorly protected SSH private keys",
                severity=Severity.HIGH,
                description="SSH private keys were found with overly permissive file permissions. Any local user might be able to read these keys and pivot laterally.",
                evidence="\n".join(keys[:20]),
                remediation="Run: chmod 600 <key_file>",
                module=self.module_name,
                check_id="crypto-009",
            ))
        return findings
