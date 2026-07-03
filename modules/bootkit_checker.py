"""Module: UEFI Secure Boot & Kernel Integrity."""
from __future__ import annotations
import os
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity

class BootkitChecker(Checker):
    module_name = "boot_integrity"

    def list_checks(self) -> List[str]:
        return [
            "Check UEFI Secure Boot enforcement status",
            "Check Kernel Integrity Measurement Architecture (IMA)",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        
        findings: List[Finding] = []
        findings += self._check_secure_boot()
        findings += self._check_ima()
        return findings

    def _check_secure_boot(self) -> List[Finding]:
        # EFI variables path
        sb_path = Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        if not sb_path.exists():
            return [Finding(
                title="UEFI Secure Boot is disabled or unavailable",
                severity=Severity.MEDIUM,
                description="The system was not booted with UEFI Secure Boot (SecureBoot efivar is missing). Bootkits can load unsigned malicious kernel modules or modify the bootloader.",
                remediation="Enable UEFI Secure Boot in the motherboard BIOS/firmware settings.",
                module=self.module_name,
                check_id="boot-001",
                category="Firmware Security",
                risk_score=50,
                affected_asset="uefi",
            )]
        
        try:
            # The last byte usually indicates the status (1 = enabled)
            with open(sb_path, "rb") as f:
                content = f.read()
                if content and content[-1] == 1:
                    pass # Secure boot is enabled
                else:
                    return [Finding(
                        title="UEFI Secure Boot is present but disabled",
                        severity=Severity.HIGH,
                        description="Secure Boot EFI variable exists but indicates it is currently disabled.",
                        remediation="Enable UEFI Secure Boot in the BIOS.",
                        module=self.module_name,
                        check_id="boot-001",
                        category="Firmware Security",
                        risk_score=70,
                        affected_asset="uefi",
                    )]
        except Exception:
            pass

        return []

    def _check_ima(self) -> List[Finding]:
        ima_path = Path("/sys/kernel/security/integrity/ima")
        if not ima_path.exists():
            return [Finding(
                title="Integrity Measurement Architecture (IMA) is disabled",
                severity=Severity.INFO,
                description="Kernel IMA is not enabled. The system cannot enforce cryptographic signature checks on executed files.",
                remediation="Configure IMA/EVM in the kernel command line parameters (ima_appraise=enforce).",
                module=self.module_name,
                check_id="boot-002",
                category="Kernel Security",
                risk_score=30,
                affected_asset="kernel-ima",
            )]
        return []
