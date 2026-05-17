from __future__ import annotations

from datetime import datetime

from .triage import compute_overdue, load_triage


def build_sla_dashboard(data_dir=None) -> dict:
    board = load_triage(data_dir)
    items = board.get("items", [])
    overdue = compute_overdue(data_dir)

    opened = 0
    closed = 0
    durations = []
    for it in items:
        created = it.get("created_at")
        updated = it.get("updated_at")
        if created:
            opened += 1
        if it.get("status") in {"mitigated", "false_positive"}:
            closed += 1
            try:
                d = datetime.fromisoformat(updated) - datetime.fromisoformat(created)
                durations.append(d.total_seconds())
            except Exception:
                pass

    mttr_h = round((sum(durations) / len(durations) / 3600), 2) if durations else 0.0
    return {"opened": opened, "closed": closed, "overdue": len(overdue), "mttr_hours": mttr_h}
