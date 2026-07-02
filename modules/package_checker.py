"""Module 3: Package Management & Software Supply Chain.

Checks:
  - Inventories installed packages (dpkg/rpm aware)
  - Matches versions against OSV.dev for known CVEs (batch API)
  - Flags missing GPG verification on package sources
  - Flags packages with available security updates
"""
from __future__ import annotations
import subprocess
import shutil
import json
import time
import urllib.request
import urllib.error
from typing import List, Dict
from core.models import Checker, Finding, Severity

# OSV batch endpoint — up to 1000 queries per request
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_BATCH_SIZE = 100   # queries per HTTP request
_OSV_RETRY_DELAY = 2.0  # seconds between retries on HTTP 429


def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


class PackageChecker(Checker):
    module_name = "package_supply_chain"

    def list_checks(self) -> List[str]:
        return [
            "Inventory installed packages (dpkg / rpm)",
            "Match installed package versions against OSV.dev CVE database (batch API)",
            "Check APT/DNF GPG signature verification is enforced",
            "Check for available security updates",
        ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        pkg_manager = self._detect_pkg_manager()

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] detected package manager: {pkg_manager}"
            )

        if self.dry_run:
            return findings

        if pkg_manager == "dpkg":
            packages = self._list_dpkg_packages()
            findings += self._check_apt_gpg()
            findings += self._check_apt_updates()
        elif pkg_manager == "rpm":
            packages = self._list_rpm_packages()
            findings += self._check_dnf_gpg()
        else:
            findings.append(Finding(
                title="Unknown package manager",
                severity=Severity.INFO,
                description="Could not detect dpkg or rpm; skipping package inventory.",
                module=self.module_name,
                check_id="pkg-000",
            ))
            return findings

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] inventoried {len(packages)} packages"
            )

        findings += self._check_cves(packages, pkg_manager)
        return findings

    # ── Detection ────────────────────────────────────────────────────────────

    def _detect_pkg_manager(self) -> str:
        if shutil.which("dpkg"):
            return "dpkg"
        if shutil.which("rpm"):
            return "rpm"
        return "unknown"

    def _list_dpkg_packages(self) -> List[Dict[str, str]]:
        out = _run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=30
        )
        pkgs = []
        for line in out.strip().splitlines():
            if "\t" in line:
                name, version = line.split("\t", 1)
                pkgs.append({"name": name, "version": version, "ecosystem": "Debian"})
        return pkgs

    def _list_rpm_packages(self) -> List[Dict[str, str]]:
        out = _run(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=30
        )
        pkgs = []
        for line in out.strip().splitlines():
            if "\t" in line:
                name, version = line.split("\t", 1)
                pkgs.append({"name": name, "version": version, "ecosystem": "RPM"})
        return pkgs

    # ── GPG / signature checks ───────────────────────────────────────────────

    def _check_apt_gpg(self) -> List[Finding]:
        """Flag APT sources that have GPG signature verification disabled."""
        import glob
        suspect_files: List[str] = []
        patterns = (
            glob.glob("/etc/apt/sources.list")
            + glob.glob("/etc/apt/sources.list.d/*.list")
            + glob.glob("/etc/apt/sources.list.d/*.sources")
        )
        for path in patterns:
            try:
                with open(path, encoding="utf-8") as fh:
                    if "trusted=yes" in fh.read():
                        suspect_files.append(path)
            except (FileNotFoundError, PermissionError):
                continue
        if suspect_files:
            return [Finding(
                title="APT source(s) with signature verification disabled",
                severity=Severity.HIGH,
                description=(
                    "One or more APT sources use [trusted=yes], which disables "
                    "GPG signature verification, allowing MITM package injection."
                ),
                evidence="\n".join(suspect_files),
                remediation=(
                    "Remove [trusted=yes] and properly import the repo's signing key "
                    "via `apt-key add` or `/etc/apt/trusted.gpg.d/`."
                ),
                cis_refs=["CIS Debian 1.2.1"],
                module=self.module_name,
                check_id="pkg-gpg-apt",
            )]
        return []

    def _check_apt_updates(self) -> List[Finding]:
        """Check for available security updates via apt-get --simulate."""
        out = _run(
            ["apt-get", "--simulate", "--just-print",
             "-o", "Dir::Etc::sourcelist=/dev/null",
             "dist-upgrade"],
            timeout=60,
        )
        # Lines like "Inst linux-image-5.x [5.y] (5.z ...)" indicate pending upgrades
        pending = [l for l in out.splitlines() if l.startswith("Inst ")]
        if pending:
            return [Finding(
                title=f"{len(pending)} package(s) have pending upgrades",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(pending)} packages have available updates. Unpatched packages "
                    f"are a primary attack surface for known CVE exploitation."
                ),
                evidence="\n".join(pending[:30]),
                remediation="Run `apt-get update && apt-get upgrade` to apply pending updates.",
                cis_refs=["CIS Linux 1.9"],
                module=self.module_name,
                check_id="pkg-updates",
            )]
        return []

    def _check_dnf_gpg(self) -> List[Finding]:
        findings = []
        try:
            with open("/etc/yum.conf", encoding="utf-8") as f:
                content = f.read()
                if "gpgcheck=0" in content.replace(" ", ""):
                    findings.append(Finding(
                        title="DNF/YUM GPG check disabled globally",
                        severity=Severity.HIGH,
                        description=(
                            "gpgcheck=0 in /etc/yum.conf disables package signature "
                            "verification for all repos."
                        ),
                        evidence="/etc/yum.conf contains gpgcheck=0",
                        remediation=(
                            "Set gpgcheck=1 in /etc/yum.conf and per-repo .repo files."
                        ),
                        cis_refs=["CIS RHEL 1.2.4"],
                        module=self.module_name,
                        check_id="pkg-gpg-dnf",
                    ))
        except FileNotFoundError:
            pass
        return findings

    # ── CVE matching via OSV.dev batch API ───────────────────────────────────

    def _check_cves(
        self, packages: List[Dict[str, str]], pkg_manager: str
    ) -> List[Finding]:
        """Batch-query OSV.dev for CVEs. Fails gracefully when offline."""
        ecosystem = "Debian" if pkg_manager == "dpkg" else "AlmaLinux"
        findings: List[Finding] = []

        for chunk_start in range(0, len(packages), _OSV_BATCH_SIZE):
            chunk = packages[chunk_start: chunk_start + _OSV_BATCH_SIZE]
            try:
                results = self._query_osv_batch(chunk, ecosystem)
            except (urllib.error.URLError, TimeoutError, OSError):
                if self.logger:
                    self.logger.warning(
                        f"[{self.module_name}] OSV.dev unreachable — skipping CVE matching."
                    )
                findings.append(Finding(
                    title="CVE matching skipped (offline / network error)",
                    severity=Severity.INFO,
                    description=(
                        "Could not reach OSV.dev to check for known CVEs in installed "
                        "packages. Re-run with network access for complete results."
                    ),
                    module=self.module_name,
                    check_id="pkg-cve-offline",
                ))
                break

            for pkg, vulns in zip(chunk, results):
                for vuln in vulns:
                    sev = self._severity_from_osv(vuln)
                    # OSV aliases field contains CVE IDs (e.g. ["CVE-2023-1234"])
                    cve_ids = vuln.get("aliases", []) or [vuln.get("id", "")]
                    findings.append(Finding(
                        title=f"Known vulnerability in {pkg['name']} {pkg['version']}",
                        severity=sev,
                        description=vuln.get("summary", "No summary provided by OSV.dev."),
                        evidence=f"Package: {pkg['name']} {pkg['version']}",
                        remediation=(
                            f"Upgrade {pkg['name']} to a patched version per the OSV advisory."
                        ),
                        cve_refs=cve_ids,
                        module=self.module_name,
                        check_id="pkg-cve",
                    ))

        return findings

    def _query_osv_batch(
        self, packages: List[Dict[str, str]], ecosystem: str
    ) -> List[List[dict]]:
        """POST to /v1/querybatch; returns one vuln list per package in order."""
        queries = [
            {"package": {"name": p["name"], "ecosystem": ecosystem}, "version": p["version"]}
            for p in packages
        ]
        body = json.dumps({"queries": queries}).encode()

        for attempt in range(3):
            req = urllib.request.Request(
                _OSV_BATCH_URL,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
                    # Each result entry has {"vulns": [...]} or {}
                    return [r.get("vulns", []) for r in data.get("results", [])]
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 2:
                    time.sleep(_OSV_RETRY_DELAY * (attempt + 1))
                    continue
                raise

        return [[] for _ in packages]  # all retries failed gracefully

    def _severity_from_osv(self, vuln: dict) -> Severity:
        """Map OSV severity entry to internal Severity enum using CVSS score."""
        for sev_entry in vuln.get("severity", []):
            # OSV severity score field is the raw CVSS vector string
            # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            score_str = sev_entry.get("score", "")
            # Extract the base score from database_specific or database score field
            # For OSV, the numeric base score is in severity[].score when type=CVSS_V3
            # but sometimes it's stored differently — attempt to extract a float
            cvss: float | None = None
            try:
                # Try direct float parse first (some entries give "9.8")
                cvss = float(score_str)
            except (ValueError, TypeError):
                pass

            if cvss is not None:
                if cvss >= 9.0:
                    return Severity.CRITICAL
                if cvss >= 7.0:
                    return Severity.HIGH
                if cvss >= 4.0:
                    return Severity.MEDIUM
                return Severity.LOW

        # Fallback: check database_specific CVSS if present
        db = vuln.get("database_specific", {})
        severity_str = db.get("severity", "").upper()
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return mapping.get(severity_str, Severity.MEDIUM)
