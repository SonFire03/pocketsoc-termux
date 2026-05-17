from __future__ import annotations

from .models import CheckResult


CATEGORY_MAP = {
    "storage_usage": "storage",
    "network_info": "network",
    "listening_ports": "network",
    "outbound_connections": "network",
    "running_processes": "process",
    "local_persistence": "persistence",
    "sensitive_permissions": "persistence",
    "package_hygiene": "packages",
    "app_inventory": "packages",
}


PENALTY = {"critical": 40, "warning": 15, "info": 5, "ok": 0}


def category_scores(checks: list[CheckResult]) -> dict[str, int]:
    buckets: dict[str, list[int]] = {}
    for check in checks:
        cat = CATEGORY_MAP.get(check.name, "other")
        buckets.setdefault(cat, []).append(PENALTY.get(check.status, 10))

    result: dict[str, int] = {}
    for cat, values in buckets.items():
        avg_penalty = sum(values) / len(values) if values else 0
        result[cat] = max(0, int(100 - avg_penalty))
    return result
