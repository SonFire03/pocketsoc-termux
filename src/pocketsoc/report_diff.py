from __future__ import annotations

import json
from pathlib import Path


def load_scan_file(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def diff_scans(a: dict, b: dict) -> dict:
    alerts_a = {x.get("id") for x in a.get("alerts", [])}
    alerts_b = {x.get("id") for x in b.get("alerts", [])}
    checks_a = {x.get("name"): x.get("status") for x in a.get("checks", [])}
    checks_b = {x.get("name"): x.get("status") for x in b.get("checks", [])}

    changed_checks = []
    for name in sorted(set(checks_a) | set(checks_b)):
        if checks_a.get(name) != checks_b.get(name):
            changed_checks.append({"check": name, "from": checks_a.get(name), "to": checks_b.get(name)})

    return {
        "new_alerts": sorted(alerts_b - alerts_a),
        "resolved_alerts": sorted(alerts_a - alerts_b),
        "changed_checks": changed_checks,
        "risk_delta": b.get("risk_score", 0) - a.get("risk_score", 0),
    }
