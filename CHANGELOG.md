# Changelog

## 0.3.0 - 2026-05-17

- Added scan history persistence in `scan-history.jsonl`.
- Added `pocketsoc trends` command.
- Added alert deduplication and risk scoring.
- Enriched Markdown report with top risks, local/UTC timestamps, and recommendations.
- Added CLI quality-of-life flags: `--quiet`, `--output`, `--fail-on-alert`, `--redact`.
- Added output redaction support for alerts and reports.
- Improved command fallbacks for Termux variants (`ifconfig`/`route`, `ps` variants).
- Added CI quality workflow (`ruff`, `mypy`, `pytest`).
- Added pre-commit config and dev tooling dependencies.

## 0.2.0 - 2026-05-17

- Added configurable thresholds via `config.json`.
- Added `pocketsoc init-config` command.
- Updated scan and alert engine to use custom thresholds.
- Improved `dashboard` with summary metrics.
- Improved `alerts` command with `--json/--table` mode.
- Extended tests for new CLI and alert behavior.

## 0.1.0 - 2026-05-17

- Initial release of PocketSOC for Termux.
- Added Typer CLI with commands: `scan`, `dashboard`, `report`, `alerts`.
- Implemented local defensive checks for storage, battery, network, ports, and processes.
- Added JSON alert generation and Markdown report export.
- Added tests and GitHub-ready project structure.
