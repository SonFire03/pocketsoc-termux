# Changelog

## 1.1.1 - 2026-05-17

- Reorganized CLI help into functional categories using Typer subcommands:
  - `scan`, `report`, `baseline`, `api`, `maint`, `config`
- Improved `--help` readability and command discoverability.

## 1.1.0 - 2026-05-17

- Added `watch` continuous scan mode.
- Added suppression rules with expiration (`suppress-add`).
- Added signed `forensics-lite` snapshot command.
- Added `integrity-monitor` for signed artifacts and bundles.
- Added API audit log for endpoint accesses.
- Added offline sensitive package intelligence in app inventory.
- Added `--dry-run` support on mutating commands.
