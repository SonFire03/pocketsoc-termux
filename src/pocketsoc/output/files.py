from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ..integrity import sign_payload, verify_payload
from ..models import ScanResult
from ..system import default_data_dir

SCHEMA_VERSION = "1.1"
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
    payload = asdict(scan)
    payload["schema_version"] = SCHEMA_VERSION
    raw = json.dumps(payload, indent=2)
    p = root / LAST_SCAN_FILE
    p.write_text(raw, encoding="utf-8")
    (root / f"{LAST_SCAN_FILE}.sig").write_text(sign_payload(raw, root), encoding="utf-8")
    append_scan_history(scan, root)
    return p


def append_scan_history(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    row = asdict(scan)
    row["schema_version"] = SCHEMA_VERSION
    p = root / HISTORY_FILE
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return p


def load_scan_history(data_dir: Path | None = None) -> list[dict]:
    p = ensure_data_dir(data_dir) / HISTORY_FILE
    if not p.exists():
        return []
    out = []
    for ln in p.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def prune_history(data_dir: Path | None = None, days: int | None = None, max_scans: int | None = None) -> int:
    history = load_scan_history(data_dir)
    if days is not None:
        cutoff = datetime.now().timestamp() - days * 86400
        tmp = []
        for row in history:
            try:
                ts = datetime.fromisoformat(row.get("timestamp", "")).timestamp()
            except Exception:
                ts = cutoff
            if ts >= cutoff:
                tmp.append(row)
        history = tmp
    if max_scans is not None and max_scans > 0:
        history = history[-max_scans:]
    p = ensure_data_dir(data_dir) / HISTORY_FILE
    p.write_text("".join(json.dumps(x) + "\n" for x in history), encoding="utf-8")
    return len(history)


def export_trends_csv(history: list[dict], data_dir: Path | None = None) -> Path:
    p = ensure_data_dir(data_dir) / TRENDS_CSV_FILE
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "alerts", "risk_score", "storage_used_pct", "schema_version"])
        for item in history:
            storage = ""
            for c in item.get("checks", []):
                if c.get("name") == "storage_usage":
                    storage = c.get("details", {}).get("used_pct", "")
                    break
            w.writerow([item.get("timestamp", ""), len(item.get("alerts", [])), item.get("risk_score", 0), storage, item.get("schema_version", SCHEMA_VERSION)])
    return p


def save_alerts(scan: ScanResult, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    payload = {"schema_version": SCHEMA_VERSION, "timestamp": scan.timestamp, "risk_score": scan.risk_score, "alerts": [asdict(a) for a in scan.alerts]}
    raw = json.dumps(payload, indent=2)
    p = root / ALERTS_FILE
    p.write_text(raw, encoding="utf-8")
    (root / f"{ALERTS_FILE}.sig").write_text(sign_payload(raw, root), encoding="utf-8")
    return p


def _load_json_signed(path: Path, data_dir: Path | None = None) -> dict:
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8")
    sig = path.parent / f"{path.name}.sig"
    if sig.exists() and not verify_payload(raw, sig.read_text(encoding="utf-8").strip(), data_dir or path.parent):
        return {"integrity_error": True}
    return json.loads(raw)


def load_last_scan(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    return _load_json_signed(root / LAST_SCAN_FILE, root)


def load_alerts(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    d = _load_json_signed(root / ALERTS_FILE, root)
    return d if d else {"schema_version": SCHEMA_VERSION, "alerts": [], "risk_score": 0}


def export_markdown_report(scan: dict, alerts: dict, data_dir: Path | None = None, report_format: str = "full") -> Path:
    root = ensure_data_dir(data_dir)
    p = root / REPORT_FILE
    if report_format == "executive":
        lines = ["# PocketSOC Executive Report", f"Timestamp: {scan.get('timestamp','n/a')}", f"Risk score: {alerts.get('risk_score',0)}", f"Alerts: {len(alerts.get('alerts',[]))}", "", "Top actions:", "- Investigate high severity alerts first", "- Close unnecessary listening ports", "- Update outdated packages"]
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    ts = scan.get("timestamp", "n/a")
    lines = ["# PocketSOC Report", f"Schema version: {scan.get('schema_version',SCHEMA_VERSION)}", f"Generated: {ts}", f"Risk score: {alerts.get('risk_score',0)}", "", "## Checks", "| Check | Status | Summary |", "| --- | --- | --- |"]
    for c in scan.get("checks", []):
        lines.append(f"| {c.get('name')} | {c.get('status')} | {c.get('summary')} |")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p
