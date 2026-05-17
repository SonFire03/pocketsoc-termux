# PocketSOC for Termux

PocketSOC is a defensive, local-only monitoring CLI for Android Termux.

## Major Commands

- `doctor`: validate local dependencies.
- `autofix-safe`: apply non-destructive bootstrap fixes.
- `serve`: read-only local API (`/health`, `/last-scan`, `/alerts`, `/trends`).
- `ui-build`: generate minimal local web UI file.
- `scan`: run signed defensive scans with profiles and output modes.
- `policy-eval`: evaluate compliance policy.
- `baseline-create` / `baseline-diff`: baseline workflow.
- `archive-rotate`: compress/sign history archives.
- `bundle`: generate incident bundle zip.
- `export`: SIEM output (`cef` or `syslog-json`).

Everything is visible with command descriptions in `pocketsoc --help`.
