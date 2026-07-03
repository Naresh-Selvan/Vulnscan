"""Core data models shared across all checker modules."""
from __future__ import annotations
import datetime
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from abc import ABC, abstractmethod

__all__ = ["Severity", "Finding", "Checker"]


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    def __str__(self) -> str:
        return self.name


def _utc_now_iso() -> str:
    """Return current UTC time as an ISO-8601 string. Compatible with Python 3.11+."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class Finding:
    """A single security finding produced by a checker module."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    cve_refs: List[str] = field(default_factory=list)
    cis_refs: List[str] = field(default_factory=list)
    module: str = ""
    check_id: str = ""
    timestamp: str = field(default_factory=_utc_now_iso)
    risk_score: int = -1          # 0-100; -1 = auto-calculate from severity
    category: str = "Security"    # Security | System Health | Performance
    affected_asset: str = ""      # e.g. specific file, service, package

    def __post_init__(self):
        if self.risk_score == -1:
            self.risk_score = {
                Severity.CRITICAL: 95,
                Severity.HIGH: 75,
                Severity.MEDIUM: 50,
                Severity.LOW: 25,
                Severity.INFO: 10,
            }.get(self.severity, 0)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": str(self.severity),
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_refs": self.cve_refs,
            "cis_refs": self.cis_refs,
            "module": self.module,
            "check_id": self.check_id,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "category": self.category,
            "affected_asset": self.affected_asset,
        }


class Checker(ABC):
    """Base interface every domain module must implement."""

    module_name: str = "base"

    def __init__(self, dry_run: bool = False, logger=None):
        self.dry_run = dry_run
        self.logger = logger

    @abstractmethod
    def list_checks(self) -> List[str]:
        """Return human-readable list of checks this module performs (for --dry-run)."""
        raise NotImplementedError

    @abstractmethod
    def run(self) -> List[Finding]:
        """Execute all checks and return findings."""
        raise NotImplementedError
