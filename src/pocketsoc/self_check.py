from __future__ import annotations

from .output.files import load_alerts, load_last_scan
from .integrity_monitor import run_integrity_monitor


def run_self_check(data_dir=None) -> dict:
    scan = load_last_scan(data_dir)
    alerts = load_alerts(data_dir)
    issues = []
    if "schema_version" not in scan:
        issues.append("missing schema_version in last_scan")
    if "alerts" not in alerts:
        issues.append("missing alerts key in alerts.json")
    integ = run_integrity_monitor(data_dir)
    if not integ.get("ok", False):
        issues.extend(integ.get("issues", []))
    return {"ok": len(issues) == 0, "issues": issues}
