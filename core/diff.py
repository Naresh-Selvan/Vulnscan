"""core/diff.py — Baseline comparison engine.

Loads a previous JSON report and compares it to a new set of findings,
producing three categories:
  - NEW      : findings not present in the baseline
  - RESOLVED : findings in the baseline that are gone now
  - PERSISTED: findings present in both (possibly with changed details)

A finding is identified by (module, check_id, title) — stable across runs.
"""
from __future__ import annotations
import json
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from .models import Finding, Severity


def _finding_key(f: dict) -> Tuple[str, str, str]:
    """Stable identity key for a finding."""
    return (f.get("module", ""), f.get("check_id", ""), f.get("title", ""))


def _dict_to_finding(d: dict) -> Finding:
    sev = Severity[d.get("severity", "INFO")]
    return Finding(
        title=d.get("title", ""),
        severity=sev,
        description=d.get("description", ""),
        evidence=d.get("evidence", ""),
        remediation=d.get("remediation", ""),
        cve_refs=d.get("cve_refs", []),
        cis_refs=d.get("cis_refs", []),
        module=d.get("module", ""),
        check_id=d.get("check_id", ""),
        timestamp=d.get("timestamp", ""),
    )


class DiffResult:
    """Container for the diff between a baseline and a current scan."""

    def __init__(
        self,
        new: List[Finding],
        resolved: List[Finding],
        persisted: List[Finding],
        baseline_path: str,
        baseline_generated_at: str,
    ):
        self.new = new
        self.resolved = resolved
        self.persisted = persisted
        self.baseline_path = baseline_path
        self.baseline_generated_at = baseline_generated_at
        self.diff_generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    @property
    def has_regressions(self) -> bool:
        """True if any HIGH/CRITICAL findings are new compared to baseline."""
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.new
        )

    def summary(self) -> dict:
        return {
            "new": len(self.new),
            "resolved": len(self.resolved),
            "persisted": len(self.persisted),
            "has_regressions": self.has_regressions,
        }

    def to_markdown(self, path: str) -> None:
        sev_emoji = {
            Severity.CRITICAL: "[CRITICAL]",
            Severity.HIGH:     "[HIGH]",
            Severity.MEDIUM:   "[MEDIUM]",
            Severity.LOW:      "[LOW]",
            Severity.INFO:     "[INFO]",
        }
        lines = [
            "# Scan Diff Report",
            "",
            f"**Baseline scan:** {self.baseline_generated_at}",
            f"**Current scan:**  {self.diff_generated_at}",
            f"**Baseline file:** {self.baseline_path}",
            "",
            "## Summary",
            "",
            f"| Category   | Count |",
            f"|------------|-------|",
            f"| NEW        | {len(self.new)} |",
            f"| RESOLVED   | {len(self.resolved)} |",
            f"| PERSISTED  | {len(self.persisted)} |",
            "",
        ]

        if self.has_regressions:
            lines += [
                "> **WARNING**: New HIGH or CRITICAL findings detected — regression!",
                "",
            ]

        def _section(title: str, findings: List[Finding], bullet: str) -> List[str]:
            if not findings:
                return [f"## {title}", "", "_None._", ""]
            out = [f"## {title}", ""]
            for f in sorted(findings, key=lambda x: -x.severity.value):
                out.append(
                    f"- {sev_emoji[f.severity]} **{f.title}** "
                    f"(`{f.module}` / `{f.check_id}`)"
                )
            out.append("")
            return out

        lines += _section("New Findings", self.new, "+")
        lines += _section("Resolved Findings", self.resolved, "-")
        lines += _section("Persisted Findings", self.persisted, "~")

        Path(path).write_text("\n".join(lines), encoding="utf-8")

    def to_json(self, path: str) -> None:
        payload = {
            "baseline_path": self.baseline_path,
            "baseline_generated_at": self.baseline_generated_at,
            "diff_generated_at": self.diff_generated_at,
            "summary": self.summary(),
            "new": [f.to_dict() for f in self.new],
            "resolved": [f.to_dict() for f in self.resolved],
            "persisted": [f.to_dict() for f in self.persisted],
        }
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_baseline(path: str) -> Tuple[Dict[Tuple, dict], str]:
    """
    Load a previous report.json. Returns (key→raw_dict, generated_at).
    Raises FileNotFoundError if path does not exist.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    generated_at = data.get("generated_at", "unknown")
    baseline_map: Dict[Tuple, dict] = {}
    for f in data.get("findings", []):
        key = _finding_key(f)
        baseline_map[key] = f
    return baseline_map, generated_at


def diff_findings(
    current: List[Finding],
    baseline_path: str,
) -> Optional[DiffResult]:
    """
    Compare current findings against a baseline JSON report.
    Returns None if baseline_path does not exist or cannot be parsed.
    """
    try:
        baseline_map, baseline_generated_at = load_baseline(baseline_path)
    except (FileNotFoundError, KeyError, json.JSONDecodeError, OSError):
        return None

    current_map: Dict[Tuple, Finding] = {}
    for f in current:
        key = (f.module, f.check_id, f.title)
        current_map[key] = f

    new_findings      = [f for key, f in current_map.items() if key not in baseline_map]
    resolved_findings = [
        _dict_to_finding(d)
        for key, d in baseline_map.items()
        if key not in current_map
    ]
    persisted_findings = [f for key, f in current_map.items() if key in baseline_map]

    return DiffResult(
        new=sorted(new_findings, key=lambda f: -f.severity.value),
        resolved=sorted(resolved_findings, key=lambda f: -f.severity.value),
        persisted=sorted(persisted_findings, key=lambda f: -f.severity.value),
        baseline_path=baseline_path,
        baseline_generated_at=baseline_generated_at,
    )
