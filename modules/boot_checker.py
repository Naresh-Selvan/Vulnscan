"""Module 5: Boot Process, GRUB & Secure Boot."""
from __future__ import annotations
import subprocess
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


class BootChecker(Checker):
    module_name = "boot_grub_secureboot"

    def list_checks(self) -> List[str]:
        return [
            "Check GRUB password protection (all grub.cfg locations)",
            "Check Secure Boot state via mokutil/bootctl",
            "Check GRUB config file permissions",
            "Check initramfs integrity / permissions",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_grub_password()
        findings += self._check_grub_permissions()
        findings += self._check_secure_boot()
        findings += self._check_initramfs()
        return findings

    def _check_grub_password(self) -> List[Finding]:
        grub_cfg_paths = [
            "/boot/grub/grub.cfg",
            "/boot/grub2/grub.cfg",
            "/boot/efi/EFI/ubuntu/grub.cfg",
            "/boot/efi/EFI/fedora/grub.cfg",
            "/boot/efi/EFI/centos/grub.cfg",
        ]
        findings = []
        found_any = False
        # Inspect ALL located grub configs, not just the first one
        for path in grub_cfg_paths:
            content = _read(path)
            if not content:
                continue
            found_any = True
            if "password_pbkdf2" in content or "set superusers" in content:
                findings.append(Finding(
                    title=f"GRUB password protection enabled ({path})",
                    severity=Severity.INFO,
                    description=(
                        "GRUB is password-protected "
                        "(set superusers / password_pbkdf2 present)."
                    ),
                    evidence=path,
                    module=self.module_name,
                    check_id="boot-001",
                ))
            else:
                findings.append(Finding(
                    title=f"GRUB has no password protection ({path})",
                    severity=Severity.MEDIUM,
                    description=(
                        "Physical or VM-console access to this machine allows an "
                        "attacker to edit kernel boot parameters (e.g. init=/bin/bash) "
                        "at the GRUB menu without any authentication."
                    ),
                    evidence=f"No password_pbkdf2 found in {path}",
                    remediation=(
                        "Set a GRUB superuser password via `grub-mkpasswd-pbkdf2` "
                        "and configure set superusers in /etc/grub.d/40_custom, "
                        "then run update-grub."
                    ),
                    cis_refs=["CIS Linux 1.4.1"],
                    module=self.module_name,
                    check_id="boot-001",
                ))
        if not found_any:
            findings.append(Finding(
                title="GRUB config not found",
                severity=Severity.INFO,
                description=(
                    "Could not locate grub.cfg at any expected path; "
                    "may be EFI-only or non-GRUB bootloader."
                ),
                module=self.module_name,
                check_id="boot-001",
            ))
        return findings

    def _check_grub_permissions(self) -> List[Finding]:
        findings = []
        for path in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]:
            p = Path(path)
            if not p.exists():
                continue
            mode = p.stat().st_mode & 0o777
            if mode & 0o077:  # group or other bits set
                findings.append(Finding(
                    title=f"GRUB config readable by non-root ({path})",
                    severity=Severity.LOW,
                    description=(
                        f"{path} has permissions {oct(mode)}, allowing non-root users "
                        f"to read bootloader configuration including any embedded secrets."
                    ),
                    evidence=f"{path}: {oct(mode)}",
                    remediation=f"Run: chmod og-rwx {path}",
                    cis_refs=["CIS Linux 1.4.2"],
                    module=self.module_name,
                    check_id="boot-002",
                ))
        return findings

    def _check_secure_boot(self) -> List[Finding]:
        # Try mokutil first (most reliable)
        if shutil.which("mokutil"):
            out = _run(["mokutil", "--sb-state"])
            if "enabled" in out.lower():
                return [Finding(
                    title="Secure Boot enabled",
                    severity=Severity.INFO,
                    description=(
                        "Secure Boot is enabled; only signed bootloaders and kernels "
                        "will load."
                    ),
                    evidence=out.strip(),
                    module=self.module_name,
                    check_id="boot-003",
                )]
            elif "disabled" in out.lower():
                return [Finding(
                    title="Secure Boot disabled",
                    severity=Severity.MEDIUM,
                    description=(
                        "Secure Boot is disabled. An attacker with physical/console "
                        "access can load unsigned kernels or bootkit-modified boot stages."
                    ),
                    evidence=out.strip(),
                    remediation=(
                        "Enable Secure Boot in firmware/UEFI settings and ensure your "
                        "bootloader is signed (shim + distro key for most Linux distros)."
                    ),
                    module=self.module_name,
                    check_id="boot-003",
                )]

        # Fallback: check EFI vars presence
        sb_path = Path("/sys/firmware/efi/efivars")
        if sb_path.exists():
            return [Finding(
                title="Secure Boot state unknown (mokutil unavailable)",
                severity=Severity.INFO,
                description=(
                    "EFI firmware detected but mokutil is not installed. Install it "
                    "to check Secure Boot state."
                ),
                remediation="apt install mokutil or dnf install mokutil, then re-run.",
                module=self.module_name,
                check_id="boot-003",
            )]
        return [Finding(
            title="Non-UEFI system — Secure Boot not applicable",
            severity=Severity.INFO,
            description="No EFI firmware detected; system is likely BIOS/legacy boot.",
            module=self.module_name,
            check_id="boot-003",
        )]

    def _check_initramfs(self) -> List[Finding]:
        boot = Path("/boot")
        if not boot.exists():
            return []
        initramfs_paths = list(boot.glob("initrd*")) + list(boot.glob("initramfs*"))
        if not initramfs_paths:
            return []
        findings = []
        for p in initramfs_paths:
            mode = p.stat().st_mode & 0o777
            # 0o044 = group-read + other-read bits
            if mode & 0o044:
                findings.append(Finding(
                    title=f"initramfs readable by non-root ({p.name})",
                    severity=Severity.LOW,
                    description=(
                        f"{p} has permissions {oct(mode)}. initramfs may contain "
                        f"sensitive key material or scripts readable by unprivileged users."
                    ),
                    evidence=f"{p}: {oct(mode)}",
                    remediation=f"chmod 600 {p}",
                    module=self.module_name,
                    check_id="boot-004",
                ))
        if self.logger:
            self.logger.info(f"[{self.module_name}] initramfs check done")
        return findings
