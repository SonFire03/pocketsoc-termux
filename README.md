# PocketSOC for Termux

![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)

PocketSOC is a lightweight, defensive, local-only monitoring CLI for Android Termux.

## What It Is

- A small Python CLI (Typer + Rich) for local health and security visibility.
- Local checks for storage, battery, network, listening ports, process inventory, sensitive permissions, package hygiene, startup persistence, outbound connections, and binary integrity.
- JSON alerts with risk scoring, deduplication, and basic correlation.
- Scan history, trend view, and CSV export.
- Baseline create/diff workflow.
- Configurable thresholds and custom rule engine.

## Commands

```bash
pocketsoc init-config
pocketsoc init-rules
pocketsoc scan
pocketsoc trends
pocketsoc baseline-create
pocketsoc baseline-diff
pocketsoc dashboard
pocketsoc report
pocketsoc alerts
```

## Useful CLI Options

- `pocketsoc scan --profile quick|standard|deep`
- `pocketsoc scan --quiet`
- `pocketsoc scan --output json`
- `pocketsoc scan --fail-on-alert medium`
- `pocketsoc scan --redact`
- `pocketsoc trends --csv`
- `pocketsoc alerts --table --redact`
- `pocketsoc report --redact`

## What It Is Not

- Not an offensive security tool.
- Not an exploit framework.
- Not an aggressive scanner.
- Not a remote attack utility.

## Safety

- Local checks only.
- No exploit logic.
- No brute-force logic.
- No remote scanning workflows.

## Output Files (`~/.pocketsoc/`)

- `config.json`
- `rules.json`
- `last_scan.json`
- `scan-history.jsonl`
- `baseline.json`
- `trends.csv`
- `alerts.json`
- `pocketsoc-report.md`
