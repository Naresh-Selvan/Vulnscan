# vulnscan — Modular OS Vulnerability Assessment Tool

> **Authorised use only.** This tool performs read-only detection, fingerprinting, and
> misconfiguration analysis. It contains no exploits, delivers no payloads, and must only
> be run against systems you have **written authorisation** to test.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites & Installation](#prerequisites--installation)
4. [Configuration](#configuration)
5. [Running the Tool](#running-the-tool)
6. [Output & Reports](#output--reports)
7. [Module Reference](#module-reference)
8. [Testing & CI/CD](#testing--cicd)

---

## Overview

`vulnscan` is a modular, plugin-style Linux host security auditor designed for
**bug bounty and authorised penetration testing** work. It checks a single host
(defaulting to localhost) against a library of detection modules covering:

- Kernel hardening flags
- Authentication, PAM & privilege management
- Package CVE exposure (via OSV.dev)
- Network exposure & firewall state
- Boot integrity (GRUB, Secure Boot)
- Desktop environment misconfigurations
- Filesystem permissions & encryption
- Logging & audit coverage
- Cryptographic configuration (TLS, SSH ciphers, entropy)
- Container security (Docker/Podman)
- Cron and Scheduled Tasks
- Process Security (in-memory implants, world-writable exes)
- Shared File Systems (NFS, SMB/Samba)

Every check is **read-only** — no files are written to the target (except output reports),
no commands are executed that modify system state.

---

## Architecture

```text
D:\Bug bounty\
├── main.py                  ← CLI entry point (click)
├── requirements.txt         ← Dependencies (pyyaml, click, pytest)
├── allowlist.example.yaml   ← Scope enforcement example
├── vulnscan.example.yaml    ← Default config overrides
│
├── core/                    ← Shared infrastructure
│   ├── models.py            ← Finding, Checker, Severity
│   ├── scope.py             ← Allowlist enforcement (scope guard)
│   ├── audit.py             ← Append-only audit logger
│   ├── report.py            ← JSON + Markdown + HTML (Chart.js) reporting
│   ├── diff.py              ← Baseline comparison engine
│   ├── config.py            ← Configuration loader
│   └── permissions.py       ← Root/sudo privileges introspection
│
├── modules/                 ← One file per security domain (13 modules)
│   ├── auth_checker.py
│   ├── boot_checker.py
│   ├── container_checker.py
│   ├── cron_checker.py      ← Scheduled tasks
│   ├── crypto_checker.py
│   ├── desktop_checker.py
│   ├── filesystem_checker.py
│   ├── kernel_checker.py
│   ├── logging_checker.py
│   ├── network_checker.py
│   ├── nfs_checker.py       ← NFS/SMB
│   ├── package_checker.py
│   └── process_checker.py   ← Process inspection
│
└── tests/                   ← Unit and smoke tests
    ├── test_models.py
    ├── test_scope.py
    ├── test_diff.py
    ├── test_report.py
    └── test_modules_smoke.py
```

Every module implements the `Checker` interface. Findings are emitted as `Finding` dataclasses and collated by `Report`. Fast modules run concurrently via `ThreadPoolExecutor` while IO-heavy modules run sequentially.

---

## Prerequisites & Installation

### System Requirements

- **Python 3.10+** (uses modern typing and syntax)
- **Linux** target (most checks read `/proc`, `/etc`, run Linux tools)
- Root or sudo access recommended for full coverage. (The tool will print a warning detailing which checks are degraded if run as a standard user).

### Install Python dependencies

```bash
cd "D:\Bug bounty"
pip install -r requirements.txt
```

---

## Configuration

### Allowlist (Mandatory)

**The tool will refuse to run without an `allowlist.yaml` file.**

```bash
cp allowlist.example.yaml allowlist.yaml
```

Set `local_only: true` to only allow scanning the current machine, or add explicit IPs/hostnames to the `targets:` list if running remotely against authorized scope.

### Configuration file (Optional)

You can generate a default configuration file to avoid passing flags repeatedly:

```bash
python main.py --init-config
```

This creates `vulnscan.yaml`, which allows you to define default values for `--target`, `--module`, `--output-dir`, `--baseline`, and `--workers`. CLI flags will always override the config file.

---

## Running the Tool

### Full scan (all modules, localhost)

```bash
sudo python main.py
```
*(Running with `sudo` is highly recommended for full visibility into /etc/shadow, audit logs, and process executables).*

### Specific module(s)

```bash
python main.py --module kernel --module auth --module nfs
```

### Dry run — list checks without executing

```bash
python main.py --dry-run
```

### Baseline Diffing

Compare a new scan against a previous run to detect regressions (new HIGH/CRITICAL findings):

```bash
python main.py --baseline reports/report.json
```
This generates `diff.md` and `diff.json`. If a regression is found, the CLI exits with code `2` (useful for CI/CD pipelines).

---

## Output & Reports

Reports are generated in the `--output-dir` (default: `reports/`).

- `report.json`: Machine-readable findings and summary metadata.
- `report.md`: Markdown summary suitable for issue trackers.
- `report.html`: Self-contained HTML report with responsive Chart.js visualisations (severity doughnut chart and module breakdown bar chart), collapsible evidence blocks, and highlighted remediation advice.

---

## Testing & CI/CD

The project includes a robust `pytest` suite testing core models, scope enforcement, diffing engine, report generation, and module smoke tests.

```bash
# Run all tests
pytest tests/ -v
```

The diffing engine (`--baseline`) makes `vulnscan` ideal for CI/CD environments. You can run it on a golden image and fail the build if a regression is introduced.
