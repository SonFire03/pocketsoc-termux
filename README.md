# PocketSOC for Termux

PocketSOC is a lightweight, defensive, local-only monitoring CLI for Android Termux.

## What It Is

- A small Python CLI (Typer + Rich) for local health and security visibility.
- A local scan runner for:
  - storage usage
  - battery information (via `termux-battery-status` when available)
  - network information (via `ip`)
  - listening ports (via `ss` or `netstat`)
  - running processes
- A basic alerting layer with JSON alert output.
- A Markdown report exporter for sharing local findings.
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
pocketsoc dashboard
pocketsoc report
pocketsoc alerts
```

Optional `--data-dir` is supported on all commands.

## Output Files

By default, PocketSOC stores data in `~/.pocketsoc/`:

- `config.json`
- `last_scan.json`
- `alerts.json`
- `pocketsoc-report.md`

## Development

Run tests:

```bash
pytest
```

## License

MIT
