# PocketSOC Sample Report (Example Data)

> This file contains sample data for documentation and demo purposes.
> It is not a live report from your device.

Generated: `{{TIMESTAMP_UTC}}`

## Scan Summary
- Profile: `standard`
- Data quality score: `92`
- Overall risk score: `14`
- Checks executed: `9`
- Alerts generated: `2`

## Device Posture
- Storage usage: `67.4%` (ok)
- Battery: `54%` (ok)
- Listening ports: `2` (warning)
- Running processes: `118` (ok)
- Package hygiene: `7 upgradable packages` (warning)

## Alert Summary
- `ALERT-PORT-SENSITIVE` (medium)
- `ALERT-PACKAGES-OUTDATED` (low)

## Observed Network Indicators (Example Ranges)
- `198.51.100.24:443`
- `203.0.113.15:53`

## Recommendations
1. Review listening services and close non-essential listeners.
2. Update outdated packages using regular Termux maintenance.
3. Re-run `pocketsoc scan run --profile deep` after updates.
4. Track alert lifecycle in triage before closure.

## Defensive Notes
- Local checks only.
- No exploit logic.
- No aggressive network scanning.
- No remote offensive actions.
