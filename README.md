# PocketSOC for Termux

![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)

PocketSOC is a lightweight, defensive, local-only monitoring CLI for Android Termux.

## What It Is

- A small Python CLI (Typer + Rich) for local health and security visibility.
- Local checks for storage, battery, network, listening ports, and running processes.
- JSON alerts with risk scoring and deduplication.
- Scan history and trend view.
- Markdown report export with recommended actions.
- Configurable local thresholds (`~/.pocketsoc/config.json`).

## What It Is Not

- Not an offensive security tool.
- Not an exploit framework.
- Not a vulnerability scanner.
- Not an aggressive network scanner.
- Not a remote attack or intrusion utility.

## Safety and Intended Usage

PocketSOC is designed for defensive, local checks on your own Termux environment. Use it only for monitoring systems and data you are authorized to inspect.

Safety boundaries:

- Local checks only.
- No exploit logic.
- No brute-force logic.
- No remote scanning workflows.

## Requirements

- Python 3.10+
- Termux-compatible environment

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Commands

```bash
pocketsoc init-config
pocketsoc scan
pocketsoc trends
pocketsoc dashboard
pocketsoc report
pocketsoc alerts
```

## Useful CLI Options

- `pocketsoc scan --quiet`
- `pocketsoc scan --output json`
- `pocketsoc scan --fail-on-alert medium`
- `pocketsoc scan --redact`
- `pocketsoc alerts --table --redact`
- `pocketsoc report --redact`

Optional `--data-dir` is supported on all commands.

## Output Files

By default, PocketSOC stores data in `~/.pocketsoc/`:

- `config.json`
- `last_scan.json`
- `scan-history.jsonl`
- `alerts.json`
- `pocketsoc-report.md`

## Development

Run quality checks:

```bash
ruff check .
mypy src
pytest
```

Enable git hooks:

```bash
pre-commit install
```

## License

MIT
