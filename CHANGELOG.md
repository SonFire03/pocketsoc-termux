# Changelog

## 0.7.0 - 2026-05-17

- Added read-only local API server (`serve`) with `/health`, `/last-scan`, `/alerts`, `/trends`.
- Added minimal local Web UI generator (`ui-build`).
- Added plugin check loader via `checks.d/*.py` (`run_check`).
- Added compliance policy initialization/evaluation (`init-policy`, `policy-eval`).
- Added alert fatigue suppression cooldown.
- Added archive rotation with gzip + signatures (`archive-rotate`).
- Added incident bundle ZIP export (`bundle`).
- Added extended command descriptions in `--help`.

## 0.6.0 - 2026-05-17
- Added doctor/autofix-safe/export/temporal-profile/baseline explain.
