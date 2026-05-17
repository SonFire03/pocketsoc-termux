# PocketSOC for Termux

PocketSOC is a defensive, local-only monitoring CLI for Android Termux.

## Core Commands

- `pocketsoc init-config` - Create threshold config presets.
- `pocketsoc init-rules` - Create custom rules template.
- `pocketsoc scan` - Run local defensive scan and persist signed artifacts.
- `pocketsoc dashboard` - Show current security posture summary.
- `pocketsoc alerts` - Show alerts in JSON or table.
- `pocketsoc report` - Export Markdown report.
- `pocketsoc trends` - Show historical evolution and export CSV.
- `pocketsoc baseline-create` - Save baseline snapshot.
- `pocketsoc baseline-diff` - Compare latest scan to baseline.
- `pocketsoc history-prune` - Prune stored scan history.
- `pocketsoc schedule-install` - Install local scheduled scan script.
- `pocketsoc verify-integrity` - Verify signed JSON artifacts.
- `pocketsoc release-tag` - Generate release tag template.

## Scan Modes

- `quick`: essential checks only
- `standard`: quick + permissions + package hygiene + startup persistence
- `deep`: standard + outbound connections + binary integrity

## Output formats

- `--output table`
- `--output json`
- `--output ndjson`

## Safety boundaries

- local checks only
- no exploit or offensive module
- no aggressive network scanning
