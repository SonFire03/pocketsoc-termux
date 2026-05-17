# Changelog

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
