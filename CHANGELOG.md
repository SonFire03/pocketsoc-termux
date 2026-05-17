# Changelog

## 1.2.0 - 2026-05-17

- Added `scan plan` for pre-execution check plan visibility.
- Added retry/backoff for transient scan checks.
- Added `report diff` to compare two scan files directly.
- Added API `/metrics` endpoint.
- Added `report audit-export` for API audit log export (JSON/CSV).
- Added suppression management (`suppress-list`, `suppress-remove`).
- Added `forensics-verify` command.
- Added global safety lock (`POCKETSOC_READONLY=1`) for mutating commands.

## 1.1.1 - 2026-05-17
- Reorganized CLI help into functional categories.
