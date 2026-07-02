#!/usr/bin/env python3
"""
vulnscan -- Modular OS Vulnerability Assessment Tool
====================================================
Authorised use only. Runs detection, fingerprinting, and misconfiguration
analysis against a single allowlisted Linux host. No exploitation.
"""
from __future__ import annotations
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import click
import concurrent.futures
import threading
from typing import List, Optional

from core.audit import get_logger
from core.scope import Allowlist, ScopeError
from core.models import Finding
from core.report import Report
from core.diff import diff_findings, DiffResult
from core.permissions import is_root, print_privilege_warning
from core import config as _cfg

# ── Module registry ───────────────────────────────────────────────────────────
MODULE_REGISTRY = {
    "kernel":     ("modules.kernel_checker",     "KernelChecker"),
    "auth":       ("modules.auth_checker",        "AuthChecker"),
    "packages":   ("modules.package_checker",     "PackageChecker"),
    "network":    ("modules.network_checker",     "NetworkChecker"),
    "boot":       ("modules.boot_checker",        "BootChecker"),
    "desktop":    ("modules.desktop_checker",     "DesktopChecker"),
    "filesystem": ("modules.filesystem_checker",  "FilesystemChecker"),
    "logging":    ("modules.logging_checker",     "LoggingChecker"),
    "crypto":     ("modules.crypto_checker",      "CryptoChecker"),
    "containers": ("modules.container_checker",   "ContainerChecker"),
    "cron":       ("modules.cron_checker",        "CronChecker"),
    "process":    ("modules.process_checker",     "ProcessChecker"),
    "nfs":        ("modules.nfs_checker",         "NfsChecker"),
}

# IO-heavy modules run sequentially to avoid hammering disk concurrently
_SEQUENTIAL_MODULES = {"filesystem", "auth", "process"}

_print_lock = threading.Lock()


def _load_checker(mod_key: str, dry_run: bool, logger):
    import importlib
    mod_path, class_name = MODULE_REGISTRY[mod_key]
    module = importlib.import_module(mod_path)
    cls = getattr(module, class_name)
    return cls(dry_run=dry_run, logger=logger)


def _banner():
    click.echo(click.style(
        "\n"
        "+------------------------------------------------------+\n"
        "|  vulnscan -- OS Vulnerability Assessment Tool        |\n"
        "|  Authorised use only | No exploitation | Read-only   |\n"
        "+------------------------------------------------------+\n",
        fg="cyan", bold=True,
    ))


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config",      "-c", default="vulnscan.yaml", show_default=True,
              help="Path to vulnscan.yaml config file (CLI flags override).")
@click.option("--allowlist",   "-a", default=None,
              help="Path to allowlist YAML. [default: from config or allowlist.yaml]")
@click.option("--module",      "-m", multiple=True,
              type=click.Choice(list(MODULE_REGISTRY.keys()) + ["all"], case_sensitive=False),
              help="Module(s) to run. Repeat for multiple. [default: all]")
@click.option("--target",      "-t", default=None,
              help="Target hostname/IP. [default: from config or localhost]")
@click.option("--dry-run",     "-n", is_flag=True, default=False,
              help="List checks without executing them.")
@click.option("--output-dir",  "-o", default=None,
              help="Report output directory. [default: from config or reports/]")
@click.option("--format",      "-f", "fmt", default=None,
              help="Report formats: json,markdown,html. [default: from config or all]")
@click.option("--log",         "-l", default=None,
              help="Audit log file path. [default: from config or vulnscan_audit.log]")
@click.option("--quiet",       "-q", is_flag=True, default=False,
              help="Suppress banner and progress output.")
@click.option("--baseline",    "-b", default=None,
              help="Path to previous report.json to diff against.")
@click.option("--parallel/--no-parallel", default=None,
              help="Run modules concurrently. [default: from config or true]")
@click.option("--workers",     default=None, type=int,
              help="Parallel worker count. [default: from config or 4]")
@click.option("--init-config", is_flag=True, default=False,
              help="Write a commented vulnscan.yaml to the current directory and exit.")
def main(
    config: str,
    allowlist: Optional[str],
    module: tuple,
    target: Optional[str],
    dry_run: bool,
    output_dir: Optional[str],
    fmt: Optional[str],
    log: Optional[str],
    quiet: bool,
    baseline: Optional[str],
    parallel: Optional[bool],
    workers: Optional[int],
    init_config: bool,
):
    """
    Modular OS vulnerability assessment tool.

    Performs read-only detection, fingerprinting, and misconfiguration analysis
    against a single allowlisted Linux host. Must not be run against targets
    not explicitly listed in the allowlist file.

    \b
    Examples:
      python main.py                                  # Full scan, localhost
      python main.py --module kernel --module auth    # Specific modules
      python main.py --dry-run                        # List checks only
      python main.py --baseline reports/report.json   # Diff against last scan
      python main.py --no-parallel                    # Sequential (debug mode)
      python main.py --init-config                    # Create vulnscan.yaml
    """

    # ── --init-config ─────────────────────────────────────────────────────────
    if init_config:
        dest = Path("vulnscan.yaml")
        if dest.exists():
            click.echo(click.style("vulnscan.yaml already exists. Skipping.", fg="yellow"))
        else:
            dest.write_text(_cfg.example_yaml(), encoding="utf-8")
            click.echo(click.style("Created vulnscan.yaml with default settings.", fg="green"))
        sys.exit(0)

    # ── Load config file, then let CLI override ───────────────────────────────
    cfg = _cfg.load(config)

    # Apply CLI overrides (only if explicitly provided)
    eff_allowlist  = allowlist   or cfg["allowlist"]
    eff_target     = target      or cfg["target"]
    eff_output_dir = output_dir  or cfg["output_dir"]
    eff_fmt        = fmt         or cfg["format"]
    eff_log        = log         or cfg["log"]
    eff_parallel   = parallel    if parallel is not None else cfg["parallel"]
    eff_workers    = workers     if workers  is not None else cfg["workers"]
    eff_baseline   = baseline    or cfg.get("baseline")

    # modules: CLI takes full precedence if provided, else config
    if module:
        eff_modules = list(module)
    else:
        eff_modules = cfg["modules"]

    # Resolve to final module list
    if "all" in [m.lower() for m in eff_modules]:
        selected = list(MODULE_REGISTRY.keys())
    else:
        selected = [m.lower() for m in eff_modules]

    if not quiet:
        _banner()

    logger = get_logger(eff_log)
    logger.info(
        f"vulnscan starting | target={eff_target} | modules={selected} | "
        f"dry_run={dry_run} | parallel={eff_parallel}"
    )

    # ── Privilege warning ──────────────────────────────────────────────────────
    if not quiet and not dry_run and not is_root():
        print_privilege_warning(selected)

    # ── Scope enforcement ──────────────────────────────────────────────────────
    if not dry_run:
        try:
            scope = Allowlist(eff_allowlist)
            scope.assert_allowed(eff_target)
        except ScopeError as e:
            click.echo(click.style(f"\n[SCOPE ERROR] {e}\n", fg="red", bold=True), err=True)
            logger.error(f"Scope check failed: {e}")
            sys.exit(1)
        except FileNotFoundError:
            click.echo(
                click.style(
                    f"\n[SCOPE ERROR] Allowlist file not found: {eff_allowlist}\n"
                    f"Create it by copying allowlist.example.yaml:\n"
                    f"  copy allowlist.example.yaml allowlist.yaml\n",
                    fg="red", bold=True,
                ),
                err=True,
            )
            sys.exit(1)
        logger.info(f"Scope check passed for target: {eff_target}")
    else:
        click.echo(click.style("  [DRY RUN] Scope check skipped.\n", fg="yellow"))

    # ── Dry-run mode ───────────────────────────────────────────────────────────
    if dry_run:
        click.echo(click.style("Checks that would run:\n", bold=True))
        for key in selected:
            checker = _load_checker(key, dry_run=True, logger=logger)
            click.echo(click.style(f"  [{key}]", fg="cyan", bold=True))
            for check in checker.list_checks():
                click.echo(f"    * {check}")
        click.echo()
        sys.exit(0)

    # ── Run modules ────────────────────────────────────────────────────────────
    all_findings: List[Finding] = []
    parallel_keys   = [k for k in selected if k not in _SEQUENTIAL_MODULES]
    sequential_keys = [k for k in selected if k in _SEQUENTIAL_MODULES]

    if eff_parallel and len(parallel_keys) > 1:
        n_workers = min(eff_workers, len(parallel_keys))
        if not quiet:
            click.echo(
                click.style(
                    f"  Running {len(parallel_keys)} modules in parallel "
                    f"({n_workers} workers)...",
                    fg="blue",
                )
            )
        results_map: dict = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
            future_to_key = {
                pool.submit(_run_module, k, False, logger, quiet): k
                for k in parallel_keys
            }
            for future in concurrent.futures.as_completed(future_to_key):
                key, findings, error = future.result()
                results_map[key] = (findings, error)
                with _print_lock:
                    if error:
                        click.echo(
                            click.style(f"    [FAIL] {key}: {error}", fg="red"), err=True
                        )
                        logger.error(f"Module {key} failed: {error}")
                    elif not quiet:
                        cnt = _count_by_severity(findings)
                        click.echo(
                            f"    [OK]  {key:14}  "
                            f"{len(findings):3} findings  {_fmt_counts(cnt)}"
                        )
                        logger.info(f"Module done: {key} | findings={len(findings)}")

        for k in parallel_keys:
            findings, _ = results_map.get(k, ([], None))
            all_findings.extend(findings)
    else:
        for key in parallel_keys:
            _run_sequential(key, logger, quiet, all_findings)

    if sequential_keys and not quiet:
        click.echo(
            click.style(
                f"\n  Running {len(sequential_keys)} IO-heavy module(s) sequentially...",
                fg="blue",
            )
        )
    for key in sequential_keys:
        _run_sequential(key, logger, quiet, all_findings)

    # ── Generate reports ───────────────────────────────────────────────────────
    out_path = Path(eff_output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    report = Report(all_findings, target=eff_target)
    formats = [f.strip().lower() for f in eff_fmt.split(",")]

    generated = []
    report_json_path = str(out_path / "report.json")

    if "json" in formats:
        report.to_json(report_json_path)
        generated.append(report_json_path)
    if "markdown" in formats:
        p = str(out_path / "report.md")
        report.to_markdown(p)
        generated.append(p)
    if "html" in formats:
        p = str(out_path / "report.html")
        report.to_html(p)
        generated.append(p)

    # ── Baseline diff ──────────────────────────────────────────────────────────
    diff: Optional[DiffResult] = None
    if eff_baseline:
        diff = diff_findings(all_findings, eff_baseline)
        if diff is None:
            click.echo(
                click.style(
                    f"  [WARN] Could not load baseline: {eff_baseline}", fg="yellow"
                ),
                err=True,
            )
        else:
            diff_md   = str(out_path / "diff.md")
            diff_json = str(out_path / "diff.json")
            diff.to_markdown(diff_md)
            diff.to_json(diff_json)
            generated += [diff_md, diff_json]
            logger.info(
                f"Diff complete | new={len(diff.new)} resolved={len(diff.resolved)} "
                f"persisted={len(diff.persisted)} regressions={diff.has_regressions}"
            )

    # ── Summary ────────────────────────────────────────────────────────────────
    if not quiet:
        counts = _count_by_severity(all_findings)
        click.echo()
        click.echo(click.style("-" * 54, fg="cyan"))
        click.echo(click.style("  SCAN COMPLETE", fg="cyan", bold=True))
        click.echo(click.style("-" * 54, fg="cyan"))
        click.echo(f"  Total findings : {len(all_findings)}")
        for sev_name, count in counts.items():
            color = {
                "CRITICAL": "red", "HIGH": "bright_red",
                "MEDIUM": "yellow", "LOW": "blue", "INFO": "white",
            }.get(sev_name, "white")
            if count:
                click.echo(f"  {click.style(sev_name, fg=color):<22}: {count}")

        if diff:
            click.echo()
            click.echo(click.style("  DIFF vs BASELINE", bold=True))
            click.echo(f"  New      : {len(diff.new)}")
            click.echo(f"  Resolved : {len(diff.resolved)}")
            click.echo(f"  Persisted: {len(diff.persisted)}")
            if diff.has_regressions:
                click.echo(
                    click.style(
                        "\n  !! REGRESSION: new HIGH/CRITICAL findings detected !!",
                        fg="red", bold=True,
                    )
                )

        if not is_root():
            click.echo(
                click.style(
                    "\n  [!] Some checks were degraded (not running as root).\n"
                    "      Re-run with: sudo python main.py\n",
                    fg="yellow",
                )
            )

        click.echo()
        for p in generated:
            click.echo(f"  >> {p}")
        click.echo()

    logger.info(
        f"vulnscan complete | total_findings={len(all_findings)} | reports={generated}"
    )

    # Exit code 2 = regressions (useful for CI pipelines)
    if diff and diff.has_regressions:
        sys.exit(2)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run_module(key: str, dry_run: bool, logger, quiet: bool):
    try:
        checker = _load_checker(key, dry_run=dry_run, logger=logger)
        findings = checker.run()
        return key, findings, None
    except Exception as exc:
        return key, [], str(exc)


def _run_sequential(key: str, logger, quiet: bool, collector: List[Finding]) -> None:
    if not quiet:
        click.echo(click.style(f"  >> Running module: {key}...", fg="blue"))
    logger.info(f"Module start: {key}")
    try:
        checker = _load_checker(key, dry_run=False, logger=logger)
        findings = checker.run()
        collector.extend(findings)
        if not quiet:
            cnt = _count_by_severity(findings)
            click.echo(
                f"     OK  {key:14}  {len(findings):3} findings  {_fmt_counts(cnt)}"
            )
        logger.info(f"Module done: {key} | findings={len(findings)}")
    except Exception as exc:
        click.echo(click.style(f"     FAIL {key}: {exc}", fg="red"), err=True)
        logger.error(f"Module {key} raised exception: {exc}")


def _count_by_severity(findings: List[Finding]) -> dict:
    from core.models import Severity
    counts = {s.name: 0 for s in reversed(list(Severity))}
    for f in findings:
        counts[f.severity.name] += 1
    return counts


def _fmt_counts(counts: dict) -> str:
    PREFIX = {
        "CRITICAL": "[C]", "HIGH": "[H]",
        "MEDIUM": "[M]", "LOW": "[L]", "INFO": "[I]",
    }
    parts = [f"{PREFIX.get(k, '')} {k}:{v}" for k, v in counts.items() if v]
    return "  ".join(parts)


if __name__ == "__main__":
    main()
