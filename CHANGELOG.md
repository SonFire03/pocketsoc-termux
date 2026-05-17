# Changelog

## 0.4.0 - 2026-05-17

- Added scan profiles: `quick`, `standard`, `deep`.
- Added new local checks: sensitive permissions, package hygiene, startup persistence, outbound connections, binary integrity.
- Added `init-rules` and custom rule engine from `rules.json`.
- Added baseline workflow: `baseline-create`, `baseline-diff`.
- Added trends CSV export with `trends --csv`.
- Added correlated high-severity alert when sensitive ports and suspicious processes coexist.
- Extended CLI help surface with new commands and options.

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
