from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ..integrity import sign_payload, verify_payload
from ..models import ScanResult
from ..system import default_data_dir

SCHEMA_VERSION = "1.0"
ALERTS_FILE = "alerts.json"
LAST_SCAN_FILE = "last_scan.json"
HISTORY_FILE = "scan-history.jsonl"
REPORT_FILE = "pocketsoc-report.md"
TRENDS_CSV_FILE = "trends.csv"


def ensure_data_dir(data_dir: Path | None = None) -> Path:
    root = data_dir or default_data_dir()
    root.mkdir(parents=True, exist_ok=True)
    return root


def save_scan(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / LAST_SCAN_FILE
    payload = asdict(scan)
    payload["schema_version"] = SCHEMA_VERSION
    raw = json.dumps(payload, indent=2)
    target.write_text(raw, encoding="utf-8")
    (root / f"{LAST_SCAN_FILE}.sig").write_text(sign_payload(raw, root), encoding="utf-8")
    append_scan_history(scan, root)
    return target


def append_scan_history(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / HISTORY_FILE
    row = asdict(scan)
    row["schema_version"] = SCHEMA_VERSION
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return target


def prune_history(data_dir: Path | None = None, days: int | None = None, max_scans: int | None = None) -> int:
    history = load_scan_history(data_dir)
    if days is not None:
        cutoff = datetime.now().timestamp() - (days * 86400)
        filtered = []
        for row in history:
            ts = row.get("timestamp")
            try:
                dt = datetime.fromisoformat(ts).timestamp()
            except Exception:
                dt = cutoff
            if dt >= cutoff:
                filtered.append(row)
        history = filtered
    if max_scans is not None and max_scans > 0:
        history = history[-max_scans:]
    root = ensure_data_dir(data_dir)
    target = root / HISTORY_FILE
    target.write_text("".join(json.dumps(r) + "\n" for r in history), encoding="utf-8")
    return len(history)


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


def export_trends_csv(history: list[dict], data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / TRENDS_CSV_FILE
    with target.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "alerts", "risk_score", "storage_used_pct", "schema_version"])
        for item in history:
            storage = ""
            for check in item.get("checks", []):
                if check.get("name") == "storage_usage":
                    storage = check.get("details", {}).get("used_pct", "")
                    break
            writer.writerow([item.get("timestamp", ""), len(item.get("alerts", [])), item.get("risk_score", 0), storage, item.get("schema_version", SCHEMA_VERSION)])
    return target


def save_alerts(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / ALERTS_FILE
    payload = {"schema_version": SCHEMA_VERSION, "timestamp": scan.timestamp, "risk_score": scan.risk_score, "alerts": [asdict(alert) for alert in scan.alerts]}
    raw = json.dumps(payload, indent=2)
    target.write_text(raw, encoding="utf-8")
    (root / f"{ALERTS_FILE}.sig").write_text(sign_payload(raw, root), encoding="utf-8")
    return target


def _load_json_signed(path: Path, data_dir: Path | None = None) -> dict:
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8")
    sig_path = path.parent / f"{path.name}.sig"
    if sig_path.exists() and not verify_payload(raw, sig_path.read_text(encoding="utf-8").strip(), data_dir or path.parent):
        return {"integrity_error": True}
    return json.loads(raw)


def load_last_scan(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    return _load_json_signed(root / LAST_SCAN_FILE, root)


def load_alerts(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    payload = _load_json_signed(root / ALERTS_FILE, root)
    if not payload:
        return {"schema_version": SCHEMA_VERSION, "alerts": [], "risk_score": 0}
    return payload


def export_markdown_report(scan: dict, alerts: dict, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / REPORT_FILE
    ts = scan.get("timestamp", "n/a")
    try:
        local_time = datetime.fromisoformat(ts).astimezone().isoformat() if ts != "n/a" else "n/a"
    except ValueError:
        local_time = "n/a"
    lines = ["# PocketSOC Report", "", f"Schema version: {scan.get('schema_version', SCHEMA_VERSION)}", f"Generated (UTC): {ts}", f"Generated (Local): {local_time}", f"Risk score: {alerts.get('risk_score', 0)}", "", "## Top Risks", ""]
    top = alerts.get("alerts", [])[:5]
    if not top:
        lines.append("No active alert.")
    else:
        for entry in top:
            lines.append(f"- {entry.get('severity', 'n/a').upper()} {entry.get('title', 'n/a')} ({entry.get('source_check', 'n/a')})")
    lines.extend(["", "## Check Results", "", "| Check | Status | Summary |", "| --- | --- | --- |"])
    for check in scan.get("checks", []):
        lines.append(f"| {check.get('name')} | {check.get('status')} | {check.get('summary')} |")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target
