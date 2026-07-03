"""Module: Binary Exploit Mitigation Analysis."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import List, Tuple
from core.models import Checker, Finding, Severity

class BinaryChecker(Checker):
    module_name = "binary_mitigations"

    def list_checks(self) -> List[str]:
        return [
            "Check core system binaries for exploit mitigations (NX, PIE, RELRO)",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        
        findings: List[Finding] = []
        findings += self._check_binary_mitigations()
        return findings

    def _check_binary_mitigations(self) -> List[Finding]:
        import shutil
        if not shutil.which("readelf"):
            if self.logger:
                self.logger.warning("readelf not found; skipping binary mitigation checks.")
            return []

        # We will check a handful of critical root-owned binaries
        # Scanning all of /usr/bin takes too long
        critical_bins = [
            "/bin/bash", "/bin/sh", "/bin/su", "/bin/ping",
            "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/ssh", "/usr/sbin/sshd"
        ]
        
        findings = []
        for b in critical_bins:
            if not os.path.exists(b):
                continue
            
            try:
                # Check for NX (Non-executable stack) and PIE (Position Independent Executable)
                # and RELRO
                out = subprocess.run(["readelf", "-Wl", b], capture_output=True, text=True, check=False).stdout
                out_dyn = subprocess.run(["readelf", "-Wd", b], capture_output=True, text=True, check=False).stdout
                
                missing_mitigations = []
                
                # Check NX
                if "GNU_STACK" in out:
                    for line in out.splitlines():
                        if "GNU_STACK" in line and "RWE" in line:
                            missing_mitigations.append("NX (Stack is executable)")
                else:
                    missing_mitigations.append("NX (GNU_STACK missing)")
                    
                # Check PIE (Type should be DYN instead of EXEC)
                out_h = subprocess.run(["readelf", "-Wh", b], capture_output=True, text=True, check=False).stdout
                if "Type:                              EXEC" in out_h:
                    missing_mitigations.append("PIE (Binary is not Position Independent)")
                    
                # Check RELRO
                if "GNU_RELRO" not in out:
                    missing_mitigations.append("RELRO (Missing GNU_RELRO)")
                elif "BIND_NOW" not in out_dyn:
                    # Partial RELRO, ideally should be Full RELRO (BIND_NOW)
                    pass

                if missing_mitigations:
                    findings.append(Finding(
                        title=f"Missing Exploit Mitigations in {b}",
                        severity=Severity.HIGH if "NX" in str(missing_mitigations) else Severity.MEDIUM,
                        description=f"The critical binary {b} is missing standard compiler exploit mitigations: {', '.join(missing_mitigations)}.",
                        evidence=f"Missing: {', '.join(missing_mitigations)}",
                        remediation="Recompile the binary with modern security flags (-fPIE, -fstack-protector-strong, -Wl,-z,relro,-z,now, -Wl,-z,noexecstack).",
                        module=self.module_name,
                        check_id=f"bin-{os.path.basename(b)}",
                        category="Binary Security",
                        risk_score=60,
                        affected_asset=b,
                    ))
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to analyze {b}: {e}")
                
        return findings
