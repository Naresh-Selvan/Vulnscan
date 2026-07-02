"""Module 6: Desktop Environment & GUI Layer."""
from __future__ import annotations
import subprocess
import os
from pathlib import Path
from typing import List
from core.models import Checker, Finding, Severity


def _run(cmd: List[str], timeout: int = 10) -> str:
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


class DesktopChecker(Checker):
    module_name = "desktop_gui"

    def list_checks(self) -> List[str]:
        return [
            "Detect display server (X11 vs Wayland)",
            "Check X11 access control (xhost)",
            "Check display manager auto-login configuration (LightDM, GDM)",
            "Check screen lock policy (gsettings / lightdm)",
            "Audit D-Bus accessible service policies",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_display_server()
        findings += self._check_x11_access()
        findings += self._check_autologin()
        findings += self._check_screen_lock()
        findings += self._check_dbus()
        return findings

    def _check_display_server(self) -> List[Finding]:
        session_type = os.environ.get("XDG_SESSION_TYPE", "")
        wayland_display = os.environ.get("WAYLAND_DISPLAY", "")
        x_display = os.environ.get("DISPLAY", "")

        if session_type == "x11" or (x_display and not wayland_display):
            return [Finding(
                title="X11 display server in use",
                severity=Severity.LOW,
                description=(
                    "X11 is the active display server. Unlike Wayland, X11 provides no "
                    "isolation between applications — any X client can capture input from "
                    "and inject events into any other application running on the same "
                    "display, including password dialogs."
                ),
                evidence=f"XDG_SESSION_TYPE={session_type}, DISPLAY={x_display}",
                remediation=(
                    "Migrate to Wayland if the desktop environment and hardware support it."
                ),
                module=self.module_name,
                check_id="gui-001",
            )]
        if session_type == "wayland" or wayland_display:
            return [Finding(
                title="Wayland display server in use",
                severity=Severity.INFO,
                description=(
                    "Wayland provides per-client isolation "
                    "(no cross-client input sniffing by default)."
                ),
                evidence=f"XDG_SESSION_TYPE={session_type}",
                module=self.module_name,
                check_id="gui-001",
            )]
        return [Finding(
            title="Display server type unknown (headless?)",
            severity=Severity.INFO,
            description="No DISPLAY or WAYLAND_DISPLAY detected. System may be headless.",
            module=self.module_name,
            check_id="gui-001",
        )]

    def _check_x11_access(self) -> List[Finding]:
        if not os.environ.get("DISPLAY"):
            return []
        out = _run(["xhost"])
        if "access control disabled" in out.lower():
            return [Finding(
                title="X11 access control disabled (xhost +)",
                severity=Severity.HIGH,
                description=(
                    "xhost reports that X11 access control is disabled, meaning ANY "
                    "local or (if networked) remote process can connect to the display, "
                    "read screen contents, and inject keystrokes."
                ),
                evidence=out.strip(),
                remediation=(
                    "Run `xhost -` to re-enable access control. Use XAUTHORITY cookie "
                    "auth instead of xhost for legitimate remote X11 needs."
                ),
                module=self.module_name,
                check_id="gui-002",
            )]
        return []

    def _check_autologin(self) -> List[Finding]:
        findings = []

        # ── LightDM ──────────────────────────────────────────────────────────
        lightdm_content = ""
        for cfg_path in ["/etc/lightdm/lightdm.conf"]:
            lightdm_content += _read(cfg_path)
        lightdm_d = Path("/etc/lightdm/lightdm.conf.d")
        if lightdm_d.is_dir():
            for f in lightdm_d.glob("*.conf"):
                lightdm_content += _read(str(f))

        # Check each line individually to avoid comment-counting heuristic errors
        for line in lightdm_content.splitlines():
            stripped = line.strip()
            # Active (non-commented) autologin-user setting
            if stripped.startswith("autologin-user=") and not stripped.startswith("#"):
                value = stripped.split("=", 1)[1].strip()
                if value:  # non-empty value means autologin is configured
                    findings.append(Finding(
                        title="LightDM auto-login configured",
                        severity=Severity.MEDIUM,
                        description=(
                            f"LightDM is configured to automatically log in '{value}' "
                            f"without requiring credentials, bypassing authentication on boot."
                        ),
                        evidence=stripped,
                        remediation=(
                            "Remove or comment out autologin-user= from lightdm.conf "
                            "to require credentials."
                        ),
                        module=self.module_name,
                        check_id="gui-003",
                    ))
                    break

        # ── GDM ──────────────────────────────────────────────────────────────
        gdm_cfg = _read("/etc/gdm3/custom.conf") or _read("/etc/gdm/custom.conf")
        for line in gdm_cfg.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "AutomaticLoginEnable" in stripped:
                # Handle both "=True" and "= True"
                val = stripped.split("=", 1)[-1].strip().lower()
                if val == "true":
                    findings.append(Finding(
                        title="GDM auto-login configured",
                        severity=Severity.MEDIUM,
                        description="GDM is configured to automatically log in a user on boot.",
                        evidence=stripped,
                        remediation=(
                            "Set AutomaticLoginEnable=False in /etc/gdm3/custom.conf."
                        ),
                        module=self.module_name,
                        check_id="gui-003",
                    ))
                break

        if self.logger:
            self.logger.info(f"[{self.module_name}] autologin check done")
        return findings

    def _check_screen_lock(self) -> List[Finding]:
        out = _run(["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"])
        if out.strip().lower() == "false":
            return [Finding(
                title="GNOME screen lock disabled",
                severity=Severity.MEDIUM,
                description=(
                    "The GNOME screensaver lock is disabled. An unattended session can "
                    "be accessed by anyone with physical or console access."
                ),
                evidence="gsettings org.gnome.desktop.screensaver lock-enabled = false",
                remediation=(
                    "Run: gsettings set org.gnome.desktop.screensaver lock-enabled true"
                ),
                cis_refs=["CIS Linux 1.8.5"],
                module=self.module_name,
                check_id="gui-004",
            )]
        return []

    def _check_dbus(self) -> List[Finding]:
        p = Path("/etc/dbus-1/system.d")
        if not p.exists():
            return []
        risky_policies: List[str] = []
        for cfg in p.glob("*.conf"):
            mode = cfg.stat().st_mode & 0o777
            if not (mode & 0o004):  # skip non-world-readable files
                continue
            content = _read(str(cfg))
            # Flag policies that have broad "allow own" or "allow send_destination='*'"
            # which expose privileged services to all callers
            if (
                'allow own="*"' in content
                or 'allow send_destination="*"' in content
                or "allow_anonymous" in content
            ):
                risky_policies.append(str(cfg))

        if risky_policies:
            return [Finding(
                title="D-Bus system policies with overly broad allow rules",
                severity=Severity.MEDIUM,
                description=(
                    "Some D-Bus system service policy files contain wildcard or "
                    "anonymous allow rules. This can expose privileged system services "
                    "to unprivileged callers."
                ),
                evidence="\n".join(risky_policies),
                remediation=(
                    "Audit each policy file and tighten <allow> rules to specific "
                    "interfaces and callers."
                ),
                module=self.module_name,
                check_id="gui-005",
            )]
        return []
