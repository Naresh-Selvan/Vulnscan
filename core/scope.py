"""Scope enforcement: refuse to run anything against non-allowlisted targets.

This is a safety guardrail, not a security boundary — the point is to make
accidental out-of-scope scanning hard, for engagements where you've defined
an explicit allowlist (e.g. bug bounty program scope docs).
"""
from __future__ import annotations
import ipaddress
import socket
import yaml
from pathlib import Path
from typing import List


class ScopeError(Exception):
    pass


# Full set of loopback addresses / names considered "localhost"
_LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", "ip6-localhost", "ip6-loopback"}
_LOCAL_NETWORK = ipaddress.ip_network("127.0.0.0/8")


def _is_loopback(addr: str) -> bool:
    """Return True for any address that resolves to the loopback network."""
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_loopback
    except ValueError:
        pass
    try:
        resolved = socket.gethostbyname(addr)
        return ipaddress.ip_address(resolved).is_loopback
    except (socket.gaierror, ValueError):
        pass
    return False


class Allowlist:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            raise ScopeError(
                f"Allowlist file not found: {path}\n"
                f"Create one (see allowlist.example.yaml) before running any scan."
            )
        with open(self.path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.targets: List[str] = data.get("targets", [])
        self.local_only: bool = data.get("local_only", True)
        if not self.targets and not self.local_only:
            raise ScopeError("Allowlist defines no targets and local_only is false.")

    def _resolve(self, host: str) -> str:
        """Resolve hostname to IP, returning host unchanged on failure."""
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            return host

    def is_allowed(self, target: str) -> bool:
        # Always allow any loopback address when local_only is enabled
        if self.local_only and (
            target in _LOCAL_NAMES
            or target == socket.gethostname()
            or _is_loopback(target)
        ):
            return True
        target_ip = self._resolve(target)
        for entry in self.targets:
            if entry == target or self._resolve(entry) == target_ip:
                return True
        return False

    def assert_allowed(self, target: str) -> None:
        if not self.is_allowed(target):
            raise ScopeError(
                f"Target '{target}' is not in the allowlist ({self.path}). "
                f"Refusing to scan. Add it explicitly if you have authorization."
            )
