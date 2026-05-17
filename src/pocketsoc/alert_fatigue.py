from __future__ import annotations

from datetime import datetime, timedelta


def suppress_repeated_alerts(alerts: list[dict], history: list[dict], cooldown_minutes: int = 5) -> list[dict]:
    if not history:
        return alerts
    cutoff = datetime.now().timestamp() - cooldown_minutes * 60
    recent_ids: set[str] = set()
    for row in history[-20:]:
        ts = row.get("timestamp")
        try:
            t = datetime.fromisoformat(ts).timestamp()
        except Exception:
            continue
        if t < cutoff:
            continue
        for a in row.get("alerts", []):
            if a.get("id"):
                recent_ids.add(a["id"])
    return [a for a in alerts if a.get("id") not in recent_ids]
