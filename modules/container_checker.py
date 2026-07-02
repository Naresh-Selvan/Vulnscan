"""Module 10: Containerisation & Namespace Security.

Checks:
  - Docker / Podman socket exposure and permissions
  - Privileged container flags
  - Dangerous capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.)
  - Namespace isolation (PID, network, user namespaces)
  - Container cgroup limits (memory / CPU)
  - Unprivileged user namespace access (kernel.unprivileged_userns_clone)
"""
from __future__ import annotations
import subprocess
import json
import shutil
from pathlib import Path
from typing import List, Dict, Any
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
        return Path(path).read_text(encoding="utf-8").strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _json(s: str) -> Any:
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return None


class ContainerChecker(Checker):
    module_name = "container_namespace"

    def list_checks(self) -> List[str]:
        return [
            "Check Docker socket permissions (/var/run/docker.sock)",
            "Check Podman socket permissions",
            "Inspect running containers for --privileged flag",
            "Inspect running containers for dangerous capabilities",
            "Inspect running containers for missing cgroup limits",
            "Check unprivileged user namespace access (kernel.unprivileged_userns_clone)",
            "Check Docker daemon configuration (no-new-privileges, userns-remap)",
        ]

    def run(self) -> List[Finding]:
        if self.dry_run:
            return []
        findings: List[Finding] = []
        findings += self._check_docker_socket()
        findings += self._check_podman_socket()
        findings += self._check_containers()
        findings += self._check_userns()
        findings += self._check_docker_daemon_config()
        return findings

    # ── Socket exposure ───────────────────────────────────────────────────────

    def _check_docker_socket(self) -> List[Finding]:
        sock = Path("/var/run/docker.sock")
        if not sock.exists():
            return [Finding(
                title="Docker socket not found",
                severity=Severity.INFO,
                description="Docker does not appear to be installed or running on this host.",
                module=self.module_name,
                check_id="ctr-001",
            )]
        mode = sock.stat().st_mode & 0o777
        findings = []
        if mode & 0o002:  # world-writable
            findings.append(Finding(
                title="Docker socket is world-writable (CRITICAL)",
                severity=Severity.CRITICAL,
                description=(
                    "/var/run/docker.sock is world-writable. Any local process can "
                    "communicate with the Docker daemon and gain root-equivalent "
                    "privileges by launching a privileged container."
                ),
                evidence=f"/var/run/docker.sock: {oct(mode)}",
                remediation=(
                    "chmod 660 /var/run/docker.sock; chown root:docker /var/run/docker.sock. "
                    "Only add trusted users to the 'docker' group."
                ),
                module=self.module_name,
                check_id="ctr-001",
            ))
        elif mode & 0o006:  # world-readable or world-read+write
            findings.append(Finding(
                title="Docker socket accessible to all users",
                severity=Severity.HIGH,
                description=(
                    "/var/run/docker.sock has read permissions for all users. "
                    "Even read-only access to the Docker socket exposes container "
                    "metadata and may allow privilege escalation."
                ),
                evidence=f"/var/run/docker.sock: {oct(mode)}",
                remediation="chmod 660 /var/run/docker.sock; restrict to docker group.",
                module=self.module_name,
                check_id="ctr-001",
            ))
        else:
            findings.append(Finding(
                title="Docker socket permissions acceptable",
                severity=Severity.INFO,
                description=f"/var/run/docker.sock: {oct(mode)} (restricted to owner/group).",
                module=self.module_name,
                check_id="ctr-001",
            ))
        if self.logger:
            self.logger.info(f"[{self.module_name}] Docker socket checked: {oct(mode)}")
        return findings

    def _check_podman_socket(self) -> List[Finding]:
        # Rootful Podman socket
        rootful = Path("/run/podman/podman.sock")
        findings = []
        if rootful.exists():
            mode = rootful.stat().st_mode & 0o777
            if mode & 0o002:
                findings.append(Finding(
                    title="Rootful Podman socket is world-writable",
                    severity=Severity.CRITICAL,
                    description=(
                        "/run/podman/podman.sock (rootful) is world-writable. "
                        "Access to the rootful Podman socket is equivalent to root access."
                    ),
                    evidence=f"{rootful}: {oct(mode)}",
                    remediation="chmod 660 /run/podman/podman.sock",
                    module=self.module_name,
                    check_id="ctr-002",
                ))
        return findings

    # ── Container inspection ──────────────────────────────────────────────────

    def _check_containers(self) -> List[Finding]:
        if not shutil.which("docker"):
            return []

        ids_out = _run(["docker", "ps", "-q"])
        container_ids = [cid.strip() for cid in ids_out.splitlines() if cid.strip()]
        if not container_ids:
            return [Finding(
                title="No running Docker containers",
                severity=Severity.INFO,
                description="No containers currently running (docker ps -q returned empty).",
                module=self.module_name,
                check_id="ctr-003",
            )]

        findings: List[Finding] = []
        privileged_containers: List[str] = []
        dangerous_cap_containers: List[str] = []
        no_limit_containers: List[str] = []

        DANGEROUS_CAPS = {
            "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE",
            "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETUID",
            "CAP_SETGID", "CAP_SYS_RAWIO", "CAP_NET_RAW",
        }

        for cid in container_ids:
            inspect_out = _run(["docker", "inspect", cid])
            data = _json(inspect_out)
            if not data or not isinstance(data, list):
                continue
            info = data[0]
            name = info.get("Name", cid).lstrip("/")
            host_config: Dict[str, Any] = info.get("HostConfig", {})

            # ── Privileged flag ───────────────────────────────────────────────
            if host_config.get("Privileged", False):
                privileged_containers.append(name)

            # ── Dangerous capabilities ────────────────────────────────────────
            cap_add = set(str(c).upper() for c in (host_config.get("CapAdd") or []))
            if "ALL" in cap_add or cap_add & DANGEROUS_CAPS:
                dangerous_cap_containers.append(
                    f"{name}: {', '.join(cap_add & (DANGEROUS_CAPS | {'ALL'}))}"
                )

            # ── cgroup limits ─────────────────────────────────────────────────
            mem_limit = host_config.get("Memory", 0)
            cpu_quota = host_config.get("CpuQuota", 0)
            if mem_limit == 0 and cpu_quota <= 0:
                no_limit_containers.append(name)

        if privileged_containers:
            findings.append(Finding(
                title="Privileged containers detected",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(privileged_containers)} container(s) are running with "
                    f"--privileged, giving them near-full host kernel access. "
                    f"A compromise of any such container is effectively a host compromise."
                ),
                evidence="\n".join(privileged_containers),
                remediation=(
                    "Remove --privileged and grant only the specific capabilities "
                    "required. Use AppArmor/seccomp profiles instead."
                ),
                cis_refs=["CIS Docker 5.4"],
                module=self.module_name,
                check_id="ctr-003",
            ))

        if dangerous_cap_containers:
            findings.append(Finding(
                title="Containers with dangerous Linux capabilities",
                severity=Severity.HIGH,
                description=(
                    f"{len(dangerous_cap_containers)} container(s) have high-privilege "
                    f"capabilities added (CAP_SYS_ADMIN, CAP_NET_RAW, etc). "
                    f"These may allow container escape or host network sniffing."
                ),
                evidence="\n".join(dangerous_cap_containers),
                remediation=(
                    "Drop all capabilities (--cap-drop ALL) and add only what is "
                    "strictly required (--cap-add <SPECIFIC_CAP>)."
                ),
                cis_refs=["CIS Docker 5.3"],
                module=self.module_name,
                check_id="ctr-004",
            ))

        if no_limit_containers:
            findings.append(Finding(
                title="Containers with no resource limits",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(no_limit_containers)} container(s) have no memory or CPU "
                    f"limits set. An uncontrolled container can exhaust host resources "
                    f"(denial of service) or mask a crypto-mining compromise."
                ),
                evidence="\n".join(no_limit_containers),
                remediation=(
                    "Set resource limits: `docker run --memory=512m --cpus=1.0 ...` "
                    "or via compose `mem_limit` / `cpus` fields."
                ),
                cis_refs=["CIS Docker 5.9"],
                module=self.module_name,
                check_id="ctr-005",
            ))

        if self.logger:
            self.logger.info(
                f"[{self.module_name}] inspected {len(container_ids)} containers"
            )
        return findings

    # ── Kernel user namespace config ──────────────────────────────────────────

    def _check_userns(self) -> List[Finding]:
        findings: List[Finding] = []

        # Debian/Ubuntu: kernel.unprivileged_userns_clone
        val = _read("/proc/sys/kernel/unprivileged_userns_clone")
        if val == "1":
            findings.append(Finding(
                title="Unprivileged user namespaces enabled",
                severity=Severity.LOW,
                description=(
                    "kernel.unprivileged_userns_clone=1 allows any unprivileged user "
                    "to create user namespaces. This is required for rootless containers "
                    "but also expands kernel attack surface (several recent kernel CVEs "
                    "required unprivileged userns access to exploit)."
                ),
                evidence="/proc/sys/kernel/unprivileged_userns_clone = 1",
                remediation=(
                    "If rootless containers are not needed, set "
                    "kernel.unprivileged_userns_clone=0 via sysctl. "
                    "If needed, ensure the kernel is fully patched."
                ),
                cis_refs=["CIS Linux 1.5.x"],
                module=self.module_name,
                check_id="ctr-006",
            ))

        # General: user.max_user_namespaces (most distros)
        max_userns = _read("/proc/sys/user/max_user_namespaces")
        if max_userns and max_userns != "0":
            try:
                count = int(max_userns)
                if count > 0:
                    findings.append(Finding(
                        title=f"User namespaces enabled (max: {count})",
                        severity=Severity.INFO,
                        description=(
                            f"user.max_user_namespaces = {count}. User namespaces "
                            f"are required by rootless Docker/Podman. "
                            f"Verify the kernel is patched for namespace-related CVEs."
                        ),
                        evidence=f"/proc/sys/user/max_user_namespaces = {count}",
                        module=self.module_name,
                        check_id="ctr-007",
                    ))
            except ValueError:
                pass

        if self.logger:
            self.logger.info(f"[{self.module_name}] userns checks done")
        return findings

    # ── Docker daemon configuration ───────────────────────────────────────────

    def _check_docker_daemon_config(self) -> List[Finding]:
        """Check /etc/docker/daemon.json for security-relevant settings."""
        content = _read("/etc/docker/daemon.json")
        if not content:
            # Docker present but no daemon.json = all defaults
            if shutil.which("docker"):
                return [Finding(
                    title="No Docker daemon.json found",
                    severity=Severity.LOW,
                    description=(
                        "Docker is installed but /etc/docker/daemon.json does not exist. "
                        "Security hardening options (userns-remap, no-new-privileges, "
                        "live-restore, log-driver) are not configured."
                    ),
                    remediation=(
                        "Create /etc/docker/daemon.json with recommended settings:\n"
                        '{"userns-remap":"default","no-new-privileges":true,'
                        '"log-driver":"json-file",'
                        '"log-opts":{"max-size":"10m","max-file":"3"}}'
                    ),
                    cis_refs=["CIS Docker 2.1", "CIS Docker 2.18"],
                    module=self.module_name,
                    check_id="ctr-008",
                )]
            return []

        cfg = _json(content) or {}
        findings: List[Finding] = []

        if not cfg.get("userns-remap"):
            findings.append(Finding(
                title="Docker userns-remap not configured",
                severity=Severity.MEDIUM,
                description=(
                    "userns-remap is not set in daemon.json. Without it, container "
                    "root (UID 0) maps to host root, meaning a container escape "
                    "immediately yields host root access."
                ),
                evidence='daemon.json: "userns-remap" not set',
                remediation='Add "userns-remap": "default" to /etc/docker/daemon.json.',
                cis_refs=["CIS Docker 2.8"],
                module=self.module_name,
                check_id="ctr-008",
            ))

        if not cfg.get("no-new-privileges", False):
            findings.append(Finding(
                title="Docker no-new-privileges not enforced",
                severity=Severity.MEDIUM,
                description=(
                    "no-new-privileges is not set globally in daemon.json. "
                    "Containers can gain new privileges via setuid binaries or "
                    "file capabilities unless this is enforced."
                ),
                evidence='daemon.json: "no-new-privileges" not set or false',
                remediation='Add "no-new-privileges": true to /etc/docker/daemon.json.',
                cis_refs=["CIS Docker 5.25"],
                module=self.module_name,
                check_id="ctr-009",
            ))

        if self.logger:
            self.logger.info(f"[{self.module_name}] Docker daemon config checked")
        return findings
