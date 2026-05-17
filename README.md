# PocketSOC for Termux

PocketSOC is a defensive, local-only monitoring CLI for Android Termux.

## New in v0.8.0

- API auth token support (`POCKETSOC_API_TOKEN`, header `X-PocketSOC-Token`).
- Dynamic web dashboard generator (`ui-build`).
- `scan --since-last` for new alerts only.
- App inventory check included in scan.
- `deps-verify` for lockfile validation.
- Executive report format (`report --format executive`).
- Config backup/restore commands.

## Commands

Run `pocketsoc --help` to see all commands and descriptions.
