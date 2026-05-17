from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ..models import ScanResult
from ..system import default_data_dir


ALERTS_FILE = "alerts.json"
LAST_SCAN_FILE = "last_scan.json"
HISTORY_FILE = "scan-history.jsonl"
REPORT_FILE = "pocketsoc-report.md"


def ensure_data_dir(data_dir: Path | None = None) -> Path:
    root = data_dir or default_data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return root


def save_scan(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / LAST_SCAN_FILE
    target.write_text(json.dumps(asdict(scan), indent=2), encoding="utf-8")
    append_scan_history(scan, root)
    return target


def append_scan_history(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / HISTORY_FILE
    target.write_text((target.read_text(encoding="utf-8") if target.exists() else "") + json.dumps(asdict(scan)) + "\n", encoding="utf-8")
    return target


def load_scan_history(data_dir: Path | None = None) -> list[dict]:
    root = ensure_data_dir(data_dir)
    target = root / HISTORY_FILE
    if not target.exists():
        return []
    rows: list[dict] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def save_alerts(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / ALERTS_FILE
    payload = {
        "timestamp": scan.timestamp,
        "risk_score": scan.risk_score,
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
        return {"alerts": [], "risk_score": 0}
    return json.loads(target.read_text(encoding="utf-8"))


def export_markdown_report(scan: dict, alerts: dict, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / REPORT_FILE

    ts = scan.get("timestamp", "n/a")
    try:
        local_time = datetime.fromisoformat(ts).astimezone().isoformat() if ts != "n/a" else "n/a"
    except ValueError:
        local_time = "n/a"

    lines = [
        "# PocketSOC Report",
        "",
        f"Generated (UTC): {ts}",
        f"Generated (Local): {local_time}",
        f"Risk score: {alerts.get('risk_score', 0)}",
        "",
        "## Top Risks",
        "",
    ]

    top = alerts.get("alerts", [])[:5]
    if not top:
        lines.append("No active alert.")
    else:
        for entry in top:
            lines.append(f"- {entry.get('severity', 'n/a').upper()} {entry.get('title', 'n/a')} ({entry.get('source_check', 'n/a')})")

    lines.extend([
        "",
        "## Check Results",
        "",
        "| Check | Status | Summary |",
        "| --- | --- | --- |",
    ])

    for check in scan.get("checks", []):
        lines.append(f"| {check.get('name')} | {check.get('status')} | {check.get('summary')} |")

    lines.extend(["", "## Alerts", ""])
    if not alerts.get("alerts"):
        lines.append("No alerts.")
    else:
        lines.append("| ID | Severity | Title | Check |")
        lines.append("| --- | --- | --- | --- |")
        for alert in alerts.get("alerts", []):
            lines.append(f"| {alert.get('id')} | {alert.get('severity')} | {alert.get('title')} | {alert.get('source_check')} |")

    lines.extend([
        "",
        "## Recommended Actions",
        "",
        "- Review high severity alerts first.",
        "- Close unnecessary listening services.",
        "- Free storage when above critical threshold.",
        "- Keep Termux packages and Android updated.",
    ])

    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target
