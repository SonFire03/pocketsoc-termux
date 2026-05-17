from __future__ import annotations

import json
from pathlib import Path

from .baseline import load_baseline
from .output.files import ensure_data_dir, load_last_scan


def write_default_policy(data_dir: Path | None = None, force: bool = False) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / "policy.json"
    if target.exists() and not force:
        return target
    policy = {"max_outdated_packages": 5, "deny_ports": ["5555", "23"]}
    target.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    return target


def eval_policy(data_dir: Path | None = None, baseline_aware: bool = False) -> dict:
    root = ensure_data_dir(data_dir)
    p = root / "policy.json"
    if not p.exists():
        write_default_policy(root)
    policy = json.loads((root / "policy.json").read_text(encoding="utf-8"))
    scan = load_last_scan(root)
    failed = []

    for check in scan.get("checks", []):
        if check.get("name") == "package_hygiene":
            cnt = check.get("details", {}).get("outdated_count", 0)
            if cnt > policy.get("max_outdated_packages", 5):
                failed.append(f"outdated packages: {cnt}")
        if check.get("name") == "listening_ports":
            ports = "\n".join(check.get("details", {}).get("ports", []))
            for denied in policy.get("deny_ports", []):
                if denied in ports:
                    failed.append(f"denied port {denied} listening")

    drift = []
    if baseline_aware:
        baseline = load_baseline(root)
        bmap = {c.get("name"): c.get("status") for c in baseline.get("checks", [])}
        for check in scan.get("checks", []):
            prev = bmap.get(check.get("name"))
            now = check.get("status")
            if prev and prev != now and now in ("warning", "critical"):
                drift.append(f"drift {check.get('name')}: {prev}->{now}")
        failed.extend(drift)

    score = max(0, 100 - len(failed) * 20)
    return {"score": score, "failed": failed, "compliant": len(failed) == 0, "baseline_aware": baseline_aware}
