# PocketSOC for Termux

> Lightweight defensive SOC toolkit for Android Termux: local monitoring, triage, evidence, and reporting.

PocketSOC is a local-first defensive monitoring toolkit for Android Termux.
It helps with visibility, triage, and evidence-oriented workflows using local telemetry and defensive-only logic.

## What PocketSOC is
- A personal defensive monitoring toolkit for Android Termux.
- Suitable for home-lab, learning, and local visibility use cases.
- Focused on local checks, triage workflow, and report/export operations.

## What PocketSOC is not
- Not an offensive framework.
- Not an exploit toolkit.
- Not a brute-force toolkit.
- Not an aggressive network scanner.
- Not a replacement for enterprise EDR, MDM, SIEM, or professional forensic platforms.

## Project Status / Maturity
PocketSOC is a personal defensive monitoring toolkit for Android Termux. It is suitable for home-lab, learning, and local visibility use cases. It is not a replacement for enterprise EDR, MDM, SIEM, or professional forensic platforms.

Current maturity:
- Actively evolving CLI with categorized command groups.
- Defensive checks and triage workflow are usable for demos and local operations.
- Experimental for broader production workflows.

## Demo
See full demo guide: [docs/demo.md](docs/demo.md)

### Quick Demo Commands
```bash
pocketsoc config init
pocketsoc scan run --profile standard
pocketsoc scan dashboard
pocketsoc scan alerts --table
pocketsoc report md --format executive
```

These commands are implemented in the current CLI.

## Example Output
Representative terminal flow:

```text
$ pocketsoc scan run --profile standard
PocketSOC Scan (...timestamp...)
- storage_usage: ok
- battery_info: ok
- listening_ports: warning
...
Risk score: 14

$ pocketsoc scan alerts --table
PocketSOC Alerts
- ALERT-PORT-SENSITIVE (medium)
- ALERT-PACKAGES-OUTDATED (low)
```

Note: actual output depends on your local device state.

## Screenshots
Screenshot capture guide: [docs/screenshots/README.md](docs/screenshots/README.md)

Recommended files:
- `docs/screenshots/scan-dashboard.png`
- `docs/screenshots/alerts-table.png`
- `docs/screenshots/report-preview.png`
- `docs/screenshots/api-health.png`

Only real screenshots should be used.

## Example Report
- Sample report (documentation-safe): [examples/sample-report.md](examples/sample-report.md)
- Examples index: [examples/README.md](examples/README.md)

## Installation
```bash
pkg update -y
pkg install -y git python

git clone https://github.com/SonFire03/pocketsoc-termux.git
cd pocketsoc-termux

python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

If `python` is unavailable on your system shell, use `python3`.

Optional Termux integration:
```bash
pkg install -y termux-api
```

## CLI Command Map
Commands are grouped for readability:
- `scan`: scan and triage operations
- `report`: reporting and export operations
- `baseline`: baseline/policy workflows
- `api`: local API and UI helpers
- `maint`: integrity/maintenance/quality tooling
- `config`: setup and local configuration

Explore:
```bash
pocketsoc --help
pocketsoc scan --help
pocketsoc report --help
pocketsoc config --help
```

## Safety Constraints
- Local checks only.
- No exploitation logic.
- No brute-force tooling.
- No aggressive network scanning.
- No remote offensive actions.

## License
MIT
