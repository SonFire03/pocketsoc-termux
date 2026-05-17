from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..models import ScanResult
from ..system import default_data_dir


ALERTS_FILE = "alerts.json"
LAST_SCAN_FILE = "last_scan.json"
REPORT_FILE = "pocketsoc-report.md"


def ensure_data_dir(data_dir: Path | None = None) -> Path:
    root = data_dir or default_data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return root


def save_scan(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / LAST_SCAN_FILE
    target.write_text(json.dumps(asdict(scan), indent=2), encoding="utf-8")
    return target


def save_alerts(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / ALERTS_FILE
    payload = {
        "timestamp": scan.timestamp,
        "alerts": [asdict(alert) for alert in scan.alerts],
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def load_last_scan(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    target = root / LAST_SCAN_FILE
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8"))


def load_alerts(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    target = root / ALERTS_FILE
    if not target.exists():
        return {"alerts": []}
    return json.loads(target.read_text(encoding="utf-8"))


def export_markdown_report(scan: dict, alerts: dict, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / REPORT_FILE

    lines = [
        "# PocketSOC Report",
        "",
        f"Generated: {scan.get('timestamp', 'n/a')}",
        "",
        "## Check Results",
        "",
        "| Check | Status | Summary |",
        "| --- | --- | --- |",
    ]

    for check in scan.get("checks", []):
        lines.append(f"| {check.get('name')} | {check.get('status')} | {check.get('summary')} |")

    lines.extend(["", "## Alerts", ""])
    if not alerts.get("alerts"):
        lines.append("No alerts.")
    else:
        lines.append("| ID | Severity | Title | Check |")
        lines.append("| --- | --- | --- | --- |")
        for alert in alerts.get("alerts", []):
            lines.append(
                f"| {alert.get('id')} | {alert.get('severity')} | {alert.get('title')} | {alert.get('source_check')} |"
            )

    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target
