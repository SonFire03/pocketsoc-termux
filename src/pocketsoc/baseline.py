from __future__ import annotations

import json
from pathlib import Path

from .output.files import ensure_data_dir, load_last_scan

BASELINE_FILE = "baseline.json"


def create_baseline(data_dir: Path | None = None, profile: str = "standard", device_id: str = "local-device") -> Path:
    root = ensure_data_dir(data_dir)
    scan = load_last_scan(root)
    scan["baseline_profile"] = profile
    scan["device_id"] = device_id
    target = root / BASELINE_FILE
    target.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    return target


def load_baseline(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    target = root / BASELINE_FILE
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8"))


def diff_baseline(current: dict, baseline: dict, tolerance: int = 0, explain: bool = False) -> dict:
    result = {
        "baseline_profile": baseline.get("baseline_profile", "unknown"),
        "device_id": baseline.get("device_id", "unknown"),
        "new_alerts": [],
        "new_checks_warning_or_critical": [],
    }
    baseline_alert_ids = {a.get("id") for a in baseline.get("alerts", [])}
    for alert in current.get("alerts", []):
        if alert.get("id") not in baseline_alert_ids:
            result["new_alerts"].append(alert)
    if tolerance and len(result["new_alerts"]) <= tolerance:
        result["new_alerts"] = []

    baseline_status = {c.get("name"): c.get("status") for c in baseline.get("checks", [])}
    for check in current.get("checks", []):
        prev = baseline_status.get(check.get("name"))
        now = check.get("status")
        if now in ("warning", "critical") and prev != now:
            result["new_checks_warning_or_critical"].append({"name": check.get("name"), "from": prev, "to": now})

    if explain:
        result["explanation"] = (
            "New alerts are IDs absent from baseline. "
            "Check drift lists checks that moved into warning/critical compared to baseline."
        )
    return result
