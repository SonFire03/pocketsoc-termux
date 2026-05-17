from __future__ import annotations

from pathlib import Path

from .bundle_sign import verify_bundle
from .output.files import ensure_data_dir, load_alerts, load_last_scan


def run_integrity_monitor(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    issues = []
    if load_last_scan(root).get("integrity_error"):
        issues.append("last_scan.json signature invalid")
    if load_alerts(root).get("integrity_error"):
        issues.append("alerts.json signature invalid")

    for z in root.glob("incident-bundle-*.zip"):
        if not verify_bundle(z, root):
            issues.append(f"bundle signature invalid: {z.name}")

    return {"ok": len(issues) == 0, "issues": issues}
