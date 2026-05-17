from __future__ import annotations

from datetime import datetime


def detect_burst(history: list[dict], window_minutes: int = 15, threshold: int = 5) -> bool:
    if len(history) < 2:
        return False
    cutoff = datetime.now().timestamp() - (window_minutes * 60)
    recent = []
    for row in history[-30:]:
        ts = row.get("timestamp", "")
        try:
            t = datetime.fromisoformat(ts).timestamp()
        except Exception:
            continue
        if t >= cutoff:
            recent.append(len(row.get("alerts", [])))
    if len(recent) < 2:
        return False
    return recent[-1] - recent[0] >= threshold
