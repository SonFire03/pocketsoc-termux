# PocketSOC for Termux

PocketSOC is a defensive, local-only monitoring CLI for Android Termux.

## Commands (with help descriptions in `pocketsoc --help`)

- `doctor`: check local dependencies/commands.
- `autofix-safe`: apply non-destructive bootstrap fixes.
- `init-config`: create threshold presets.
- `init-rules`: create custom rules template.
- `scan`: run local signed scan (`--profile`, `--time-profile`, `--output ndjson`).
- `dashboard`: summary + checks view.
- `alerts`: alert table/JSON.
- `report`: markdown report export.
- `trends`: timeline view + `--csv` export.
- `baseline-create`: create baseline with profile/device id.
- `baseline-diff`: compare latest scan to baseline (`--explain`).
- `history-prune`: retention by days/count.
- `schedule-install`: install local scheduled scan script.
- `verify-integrity`: verify signed payloads.
- `export`: SIEM export (`cef` or `syslog-json`).
- `release-tag`: release helper.

## Security/Hardening

- Signed scan artifacts (`.sig`) for tamper evidence.
- Rules engine supports AND/OR + regex.
- Baseline diff with tolerance and explanation.
- Dependency lock file: `requirements-lock.txt`.
