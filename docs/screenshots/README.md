# Screenshots Guide

Do not use fake screenshots. Capture real command output from your local run.

## Pre-capture commands
Run these first:

```bash
pocketsoc config init
pocketsoc scan run --profile standard
pocketsoc scan dashboard
pocketsoc scan alerts --table
pocketsoc report md --format executive
curl -s http://127.0.0.1:8787/health
```

If API is needed in parallel:

```bash
pocketsoc api serve --host 127.0.0.1 --port 8787
```

## Recommended screenshots
- `scan-dashboard.png`
- `alerts-table.png`
- `report-preview.png`
- `api-health.png`

## Capture settings
- Terminal size: `120x35` recommended.
- Use a readable font and consistent theme.
- Avoid showing private tokens, usernames, or local sensitive paths.

## Naming guidance
Use lowercase kebab-case names:
- good: `scan-dashboard.png`
- avoid: `Screenshot 1.png`

## Add images to README
Store images in `docs/screenshots/` and reference like:

```md
![Scan Dashboard](docs/screenshots/scan-dashboard.png)
```

Use only real captures from the current CLI behavior.
