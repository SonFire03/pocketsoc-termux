# Changelog

## 0.6.0 - 2026-05-17

- Added `doctor` command for environment diagnostics.
- Added `autofix-safe` command for non-destructive local fixes.
- Added SIEM export command (`export --fmt cef|syslog-json`).
- Added Termux local notifications on high risk.
- Added temporal scan profile option (`--time-profile auto|day|night`).
- Added baseline multi-host metadata (`device_id`) and `--explain` diff mode.
- Added dependency lock file (`requirements-lock.txt`).
- Kept all command descriptions visible in `--help`.

## 0.5.0 - 2026-05-17
- Added signed artifacts, pruning, scheduling, and richer help.
