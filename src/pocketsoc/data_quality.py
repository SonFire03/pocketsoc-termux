from __future__ import annotations


def compute_data_quality(checks: list[dict]) -> dict:
    total = len(checks)
    info = sum(1 for c in checks if c.get("status") == "info")
    warn = sum(1 for c in checks if c.get("status") == "warning")
    score = max(0, 100 - (info * 5 + warn * 3)) if total else 0
    return {"score": score, "total_checks": total, "info_checks": info, "warning_checks": warn}
