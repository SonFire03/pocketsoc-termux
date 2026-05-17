# PocketSOC for Termux

> Lightweight defensive SOC toolkit for Android Termux: local monitoring, triage, evidence, and reporting.

PocketSOC is a defensive, local-first security operations toolkit for Android Termux.
It provides continuous host visibility, structured alerting, triage workflow, evidence handling, and export/reporting capabilities with zero offensive functionality.

## Table of Contents
- [Overview](#overview)
- [Security Model](#security-model)
- [Feature Set](#feature-set)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Command Map](#cli-command-map)
- [Operational Workflows](#operational-workflows)
- [API Reference](#api-reference)
- [Data, Integrity, and Evidence](#data-integrity-and-evidence)
- [Configuration](#configuration)
- [Compliance and Policy](#compliance-and-policy)
- [Release and Quality](#release-and-quality)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview
PocketSOC is designed for practitioners who need a lightweight SOC-like experience directly in Termux:

- Local telemetry collection (storage, battery, process, ports, network, package hygiene, persistence indicators)
- Alert generation with severity and risk scoring
- Triage lifecycle management (status, owner, SLA, comments, templates)
- Signed artifacts and chain-of-evidence primitives
- API/UI surfaces for local investigation
- Incident packaging, reporting, and SIEM-friendly exports

Target use cases:
- Personal mobile security monitoring
- Home-lab endpoint telemetry
- Local forensic-lite snapshots
- Automated local compliance checks

## Security Model
PocketSOC is intentionally defensive and constrained.

What it does:
- Local inspection only
- Passive data collection from host commands
- Signed evidence and integrity checks
- Structured triage and reporting

What it does not do:
- No exploitation logic
- No brute-force tooling
- No aggressive network scanning
- No remote offensive actions

## Feature Set
### Detection and Monitoring
- Profile-based scans: `quick`, `standard`, `deep`
- Optional parallel collection and retry/backoff for transient checks
- Statistical anomaly overlays and burst detection
- Category-level health scoring

### Triage and Response
- Persistent triage board with statuses:
  - `new`, `investigating`, `mitigated`, `false_positive`
- Auto-routing by severity/check type
- Transition guardrails (state-machine validation)
- Comment templates and templated triage apply
- SLA dashboard (overdue count, MTTR, opened/closed)

### Integrity and Evidence
- Signed scan and alert artifacts
- Integrity monitor for artifacts and bundle signatures
- Forensics-lite signed snapshots
- Incident timeline generation
- Evidence hash-chain verification

### Reporting and Exports
- Markdown reports (`full`, `executive`, baseline comparison)
- Direct scan-to-scan diff reports
- CSV trends export
- SIEM export (`cef`, `syslog-json`)
- Incident bundle and incident pack exports

### API and UI
- Local API with token auth support
- Built-in rate limiting (`429` on exceeded budget)
- Endpoints for scans, alerts, trends, metrics, timeline
- `POST /alert-state` for triage updates
- Local web UI generation with filters and inline ack action

## Installation
### Requirements
- Python 3.10+
- Termux environment

### Setup
```bash
pkg update -y
pkg install -y git python

git clone https://github.com/SonFire03/pocketsoc-termux.git
cd pocketsoc-termux

python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Optional Termux integrations:
```bash
pkg install -y termux-api
```
Also install the Android **Termux:API** app for notification/battery APIs.

## Quick Start
```bash
# 1) initialize local config artifacts
pocketsoc config init
pocketsoc config rules
pocketsoc config policy --pack home-lab

# 2) run a scan
pocketsoc scan run --profile standard

# 3) view posture
pocketsoc scan dashboard
pocketsoc scan alerts --table

# 4) export report
pocketsoc report md --format executive
```

## CLI Command Map
PocketSOC commands are grouped by category for discoverability.

- `scan`:
  - `plan`, `run`, `watch`, `dashboard`, `alerts`, `search`, `explain-alert`, `triage-apply`, `triage-template`
- `report`:
  - `md`, `diff`, `timeline`, `sla`, `triage-analytics`, `trends`, `export`, `audit-export`, `incident-pack`, `bundle`, `bundle-decrypt`, `bundle-verify`
- `baseline`:
  - `create`, `diff`, `policy-eval`, `policy-sim`
- `api`:
  - `serve`, `key-rotate`, `ui-build`
- `maint`:
  - `doctor`, `integrity-monitor`, `verify-integrity`, `evidence-verify`, `forensics-lite`, `forensics-verify`, `history-prune`, `archive-rotate`, `schedule-install`, `release-notes`, `quality-gate`, `self-check`
- `config`:
  - `init`, `rules`, `policy`, `comment-templates`, `backup`, `backup-verify`, `restore`, `deps-verify`, `suppress-add`, `suppress-list`, `suppress-remove`, `autofix-safe`

Get full help anytime:
```bash
pocketsoc --help
pocketsoc scan --help
```

## Operational Workflows
### Continuous Monitoring
```bash
pocketsoc scan watch --interval 120 --profile standard
```

### Triage Loop
```bash
pocketsoc scan alerts --json
pocketsoc scan triage-apply ALERT-ID high --status investigating --owner oncall
pocketsoc report sla
```

### Incident Handling
```bash
pocketsoc report timeline
pocketsoc maint forensics-lite
pocketsoc report incident-pack
pocketsoc report bundle --redact --encrypt-password 'strong-passphrase'
pocketsoc report bundle-verify /path/to/bundle.zip.enc
```

## API Reference
Default bind:
```bash
pocketsoc api serve --host 127.0.0.1 --port 8787
```

Authentication:
- Set `POCKETSOC_API_TOKEN` to enforce token checks
- Send header `X-PocketSOC-Token: <token>`

Endpoints:
- `GET /health`
- `GET /last-scan`
- `GET /alerts?severity=high&limit=50`
- `GET /trends?limit=50`
- `GET /timeline?limit=200`
- `GET /metrics`
- `POST /alert-state`

Rate limiting:
- Sliding-window limiter per `client_ip:endpoint`
- Exceeded budget returns `429`

## Data, Integrity, and Evidence
Default data directory:
- `~/.pocketsoc/`

Typical files:
- `last_scan.json`, `last_scan.json.sig`
- `alerts.json`, `alerts.json.sig`
- `scan-history.jsonl`
- `triage-board.json`
- `api-audit.log`
- `evidence-chain.jsonl`
- `baseline.json`
- `pocketsoc-report.md`

Verification commands:
```bash
pocketsoc maint verify-integrity
pocketsoc maint integrity-monitor
pocketsoc maint evidence-verify
```

## Configuration
Bootstrap:
```bash
pocketsoc config init
pocketsoc config rules
pocketsoc config policy --pack strict-mobile
```

Suppression management:
```bash
pocketsoc config suppress-add "ALERT-PROC-SUSPICIOUS"
pocketsoc config suppress-list
pocketsoc config suppress-remove 1
```

Read-only lock (safety mode):
```bash
export POCKETSOC_READONLY=1
```
This blocks mutating commands until unset.

## Compliance and Policy
Evaluate current state:
```bash
pocketsoc baseline policy-eval --baseline-aware
```

Simulate policy packs on history:
```bash
pocketsoc baseline policy-sim
```

## Release and Quality
Project quality gates:
```bash
pytest -q
pocketsoc maint quality-gate
```

Generate release-note draft from changelog:
```bash
pocketsoc maint release-notes
```

## Troubleshooting
### Missing Termux commands
Run:
```bash
pocketsoc maint doctor --fix-hints
```

### Backup integrity
```bash
pocketsoc config backup
pocketsoc config backup-verify
```

### Encrypted bundle decryption failure
- Verify password correctness
- Ensure `cryptography` is installed

## License
MIT
