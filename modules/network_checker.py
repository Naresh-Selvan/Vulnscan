"""Module 4: Network Stack, Services & Firewall."""
from __future__ import annotations
import subprocess
import shutil
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity


def _run(cmd: List[str], timeout: int = 15) -> str:
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


class NetworkChecker(Checker):
    module_name = "network_firewall"

    def list_checks(self) -> List[str]:
        return [
            "Inventory listening ports and services (ss/netstat)",
            "Audit firewall state (iptables / nftables / ufw)",
            "Check for IPv6 exposure",
            "Check for unnecessary services enabled at boot (systemctl)",
            "Audit IPv4 forwarding and source routing (sysctl)",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_listening_ports()
        findings += self._check_firewall()
        findings += self._check_ipv6()
        findings += self._check_boot_services()
        findings += self._check_sysctl_routing()
        return findings

    def _check_listening_ports(self) -> List[Finding]:
        out = _run(["ss", "-tlnup"]) or _run(["netstat", "-tlnup"])
        if not out:
            return [Finding(
                title="Could not inventory listening ports",
                severity=Severity.INFO,
                description="ss and netstat both unavailable.",
                module=self.module_name,
                check_id="net-001a",  # distinct ID
            )]
        if self.logger:
            self.logger.info(f"[{self.module_name}] listening ports collected")

        high_risk_ports = {
            "21": "FTP", "23": "Telnet", "512": "rexec",
            "513": "rlogin", "514": "rsh/syslog",
        }
        hits = []
        for line in out.splitlines()[1:]:  # skip header
            for port, svc in high_risk_ports.items():
                if f":{port} " in line or line.endswith(f":{port}"):
                    hits.append(f"Port {port} ({svc}): {line.strip()}")

        findings = [Finding(
            title="Listening port inventory",
            severity=Severity.INFO,
            description="Full list of TCP/UDP listeners on this host.",
            evidence=out[:3000],
            module=self.module_name,
            check_id="net-001",   # inventory finding
        )]
        if hits:
            findings.append(Finding(
                title="Dangerous legacy services listening",
                severity=Severity.HIGH,
                description=(
                    "One or more high-risk / cleartext services are exposed on the "
                    "network stack (FTP, Telnet, rsh, etc). These transmit credentials "
                    "in plaintext and should not be running."
                ),
                evidence="\n".join(hits),
                remediation="Disable or remove legacy services; replace with SSH/SFTP.",
                cis_refs=["CIS Linux 2.1"],
                module=self.module_name,
                check_id="net-002",  # separate finding ID
            ))
        return findings

    def _check_firewall(self) -> List[Finding]:
        findings: List[Finding] = []

        # ── ufw ──────────────────────────────────────────────────────────────
        if shutil.which("ufw"):
            out = _run(["ufw", "status"])
            if "inactive" in out.lower():
                findings.append(Finding(
                    title="UFW firewall is inactive",
                    severity=Severity.HIGH,
                    description=(
                        "ufw is installed but not active. No host-based firewall is "
                        "enforcing traffic restrictions."
                    ),
                    evidence=out.strip(),
                    remediation="Enable ufw: `sudo ufw enable` and define appropriate rules.",
                    cis_refs=["CIS Linux 3.5.1"],
                    module=self.module_name,
                    check_id="net-003",
                ))
            else:
                findings.append(Finding(
                    title="UFW firewall active",
                    severity=Severity.INFO,
                    description="ufw is active.",
                    evidence=out[:500],
                    module=self.module_name,
                    check_id="net-003",
                ))
            return findings  # ufw takes precedence; skip iptables/nftables

        # ── iptables fallback ────────────────────────────────────────────────
        if shutil.which("iptables"):
            out = _run(["iptables", "-L", "-n", "--line-numbers"])
            # Only flag "no effective rules" when iptables returned non-empty output
            # and every line matches a default ACCEPT chain header or column header
            ACCEPT_PATTERNS = {
                "Chain INPUT (policy ACCEPT)",
                "Chain FORWARD (policy ACCEPT)",
                "Chain OUTPUT (policy ACCEPT)",
                "target     prot opt source               destination",
                "",
            }
            lines = out.splitlines()
            if lines and all(l.strip() in ACCEPT_PATTERNS for l in lines):
                findings.append(Finding(
                    title="iptables has no effective rules",
                    severity=Severity.HIGH,
                    description=(
                        "iptables default policy is ACCEPT with no filtering rules, "
                        "leaving all ports open to the network."
                    ),
                    evidence=out[:800],
                    remediation=(
                        "Define iptables rules appropriate for this host's role, "
                        "or install and enable ufw/firewalld."
                    ),
                    cis_refs=["CIS Linux 3.5.3"],
                    module=self.module_name,
                    check_id="net-003",
                ))
            elif lines:
                findings.append(Finding(
                    title="iptables rules present",
                    severity=Severity.INFO,
                    description="iptables has active rules (manual review recommended).",
                    evidence=out[:1000],
                    module=self.module_name,
                    check_id="net-003",
                ))

        # ── nftables fallback ────────────────────────────────────────────────
        if shutil.which("nft"):
            out = _run(["nft", "list", "ruleset"])
            if not out.strip():
                findings.append(Finding(
                    title="nftables ruleset is empty",
                    severity=Severity.HIGH,
                    description="nft is present but the ruleset is empty — no packet filtering.",
                    remediation="Define an nftables ruleset appropriate for this host.",
                    cis_refs=["CIS Linux 3.5.2"],
                    module=self.module_name,
                    check_id="net-003",
                ))
        return findings

    def _check_ipv6(self) -> List[Finding]:
        disabled = _read("/proc/sys/net/ipv6/conf/all/disable_ipv6").strip()
        if disabled != "1":
            return [Finding(
                title="IPv6 enabled but may not be firewalled",
                severity=Severity.LOW,
                description=(
                    "IPv6 is enabled. Firewalls that only configure iptables (IPv4) "
                    "may leave IPv6 traffic completely unfiltered. Verify ip6tables or "
                    "nftables rules cover IPv6 equivalently."
                ),
                evidence=f"/proc/sys/net/ipv6/conf/all/disable_ipv6 = {disabled or '(not found)'}",
                remediation=(
                    "Either disable IPv6 if unused (net.ipv6.conf.all.disable_ipv6=1) "
                    "or explicitly extend firewall rules to cover ip6tables."
                ),
                cis_refs=["CIS Linux 3.3"],
                module=self.module_name,
                check_id="net-004",
            )]
        return []

    def _check_boot_services(self) -> List[Finding]:
        HIGH_RISK_SERVICES = [
            "telnet", "rsh", "rlogin", "rexec", "tftp", "vsftpd", "xinetd",
            "avahi-daemon", "cups", "nfs-server", "rpcbind", "talk", "ntalk",
        ]
        out = _run(["systemctl", "list-unit-files", "--state=enabled", "--type=service"])
        if not out:
            return []

        # Match whole service names (e.g. "cups.service") to avoid substring false positives
        hits = []
        for svc in HIGH_RISK_SERVICES:
            if f"{svc}.service" in out.lower() or f"{svc}d.service" in out.lower():
                hits.append(svc)

        if self.logger:
            self.logger.info(f"[{self.module_name}] boot services checked")
        if hits:
            return [Finding(
                title="High-risk services enabled at boot",
                severity=Severity.MEDIUM,
                description=(
                    "One or more legacy or unnecessary services are enabled and will "
                    "start automatically at boot, expanding the permanent attack surface."
                ),
                evidence="\n".join(hits),
                remediation="Disable each unneeded service: `systemctl disable --now <svc>`.",
                cis_refs=["CIS Linux 2.1", "CIS Linux 2.2"],
                module=self.module_name,
                check_id="net-005",
            )]
        return []

    def _check_sysctl_routing(self) -> List[Finding]:
        findings = []
        
        # Check IP forwarding
        ip_forward = _read("/proc/sys/net/ipv4/ip_forward").strip()
        if ip_forward == "1":
            findings.append(Finding(
                title="IPv4 Forwarding is enabled",
                severity=Severity.LOW,
                description=(
                    "IP forwarding is enabled (net.ipv4.ip_forward = 1). Unless this host "
                    "is specifically functioning as a router or VPN gateway, this should be "
                    "disabled to prevent the host from acting as a network bridge for attackers."
                ),
                evidence="/proc/sys/net/ipv4/ip_forward = 1",
                remediation="Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf",
                cis_refs=["CIS Linux 3.1.1"],
                module=self.module_name,
                check_id="net-003",
            ))
            
        # Check source routing
        source_route = _read("/proc/sys/net/ipv4/conf/all/accept_source_route").strip()
        if source_route == "1":
            findings.append(Finding(
                title="Source Routing is enabled",
                severity=Severity.MEDIUM,
                description=(
                    "The host is configured to accept IPv4 source-routed packets "
                    "(net.ipv4.conf.all.accept_source_route = 1). This allows an attacker to "
                    "dictate the network path of a packet, bypassing routing table security."
                ),
                evidence="/proc/sys/net/ipv4/conf/all/accept_source_route = 1",
                remediation="Set net.ipv4.conf.all.accept_source_route = 0 in /etc/sysctl.conf",
                cis_refs=["CIS Linux 3.2.1"],
                module=self.module_name,
                check_id="net-004",
            ))
            
        return findings
