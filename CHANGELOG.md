# Changelog

## 0.5.0 - 2026-05-17

- Added tamper-evident signatures for `last_scan.json` and `alerts.json`.
- Added `verify-integrity` command.
- Added history retention command: `history-prune --days/--max-scans`.
- Added local scheduling helper: `schedule-install`.
- Added baseline tolerance and profile annotation.
- Upgraded rules engine to support `AND`/`OR` + regex conditions.
- Added `--output ndjson` and schema version markers.
- Improved command help descriptions across all CLI commands.

## 0.4.0 - 2026-05-17
- Added advanced local scans, baseline, and rules.
