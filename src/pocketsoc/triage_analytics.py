from __future__ import annotations

from collections import Counter
from datetime import datetime

from .triage import load_triage


def triage_stats(data_dir=None) -> dict:
    items = load_triage(data_dir).get("items", [])
    by_owner = Counter(i.get("owner", "") for i in items)
    by_sev = Counter(i.get("severity", "") for i in items)
    by_status = Counter(i.get("status", "") for i in items)

    mt = []
    for i in items:
        c = i.get("created_at")
        u = i.get("updated_at")
        if c and u:
            try:
                mt.append((datetime.fromisoformat(u) - datetime.fromisoformat(c)).total_seconds() / 3600)
            except Exception:
                pass
    return {
        "count": len(items),
        "by_owner": dict(by_owner),
        "by_severity": dict(by_sev),
        "by_status": dict(by_status),
        "avg_hours_to_update": round(sum(mt) / len(mt), 2) if mt else 0,
    }
