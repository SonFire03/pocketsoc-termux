from __future__ import annotations

from typing import Any

from .compliance_packs import PACKS
from .output.files import load_scan_history


def simulate_policies(data_dir=None) -> dict:
    history = load_scan_history(data_dir)[-50:]
    results: dict[str, dict] = {}
    packs: dict[str, dict[str, Any]] = PACKS
    for name, policy in packs.items():
        fails = 0
        for row in history:
            row_failed = 0
            for check in row.get("checks", []):
                if check.get("name") == "package_hygiene":
                    if check.get("details", {}).get("outdated_count", 0) > policy.get("max_outdated_packages", 5):
                        row_failed += 1
                if check.get("name") == "listening_ports":
                    ports = "\n".join(check.get("details", {}).get("ports", []))
                    if any(p in ports for p in policy.get("deny_ports", [])):
                        row_failed += 1
            if row_failed:
                fails += 1
        results[name] = {"scans_evaluated": len(history), "failed_scans": fails, "pass_rate": (0 if not history else round((len(history) - fails) / len(history) * 100, 2))}
    return results
