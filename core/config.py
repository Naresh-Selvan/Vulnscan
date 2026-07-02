"""core/config.py — Optional vulnscan.yaml configuration file loader.

If a vulnscan.yaml (or --config path) exists, its values are used as CLI
defaults. Command-line flags always take precedence over config file values.

Supported keys mirror the CLI options:
  target, allowlist, output_dir, format, log, parallel, workers,
  modules (list), baseline
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Optional


_DEFAULTS: Dict[str, Any] = {
    "target":      "localhost",
    "allowlist":   "allowlist.yaml",
    "output_dir":  "reports",
    "format":      "json,markdown,html",
    "log":         "vulnscan_audit.log",
    "parallel":    True,
    "workers":     4,
    "modules":     ["all"],
    "baseline":    None,
}


def load(config_path: str = "vulnscan.yaml") -> Dict[str, Any]:
    """
    Load configuration from a YAML file. Missing keys fall back to _DEFAULTS.
    Returns a flat dict with the same keys as _DEFAULTS.
    Raises no exceptions — if the file does not exist or is malformed,
    the default dict is returned.
    """
    result = dict(_DEFAULTS)
    p = Path(config_path)
    if not p.exists():
        return result
    try:
        import yaml  # pyyaml is in requirements.txt
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return result  # malformed YAML → ignore silently

    if not isinstance(raw, dict):
        return result

    for key in _DEFAULTS:
        if key in raw and raw[key] is not None:
            result[key] = raw[key]

    # Normalise modules: always a list of strings
    if isinstance(result["modules"], str):
        result["modules"] = [m.strip() for m in result["modules"].split(",")]

    return result


def example_yaml() -> str:
    """Return a commented example vulnscan.yaml content string."""
    return """\
# vulnscan.yaml — Default configuration for vulnscan
# Command-line flags always override these values.

# Target host to scan (must match an entry in allowlist.yaml)
target: localhost

# Path to the allowlist file
allowlist: allowlist.yaml

# Output directory for reports
output_dir: reports

# Report formats to generate (comma-separated or YAML list)
format: json,markdown,html

# Append-only audit log path
log: vulnscan_audit.log

# Run modules in parallel (true/false)
parallel: true

# Number of parallel worker threads
workers: 4

# Modules to run by default (list or 'all')
modules:
  - all

# Path to a previous report.json to diff against (leave blank to skip)
# baseline: reports/report.json
"""
