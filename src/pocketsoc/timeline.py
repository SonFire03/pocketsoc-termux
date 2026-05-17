from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .output.files import load_scan_history, ensure_data_dir
from .triage import load_triage


def build_timeline(data_dir: Path | None = None) -> list[dict]:
    events: list[dict] = []
    history = load_scan_history(data_dir)
    for row in history:
        events.append({"ts": row.get("timestamp"), "type": "scan", "risk_score": row.get("risk_score", 0), "alerts_count": len(row.get("alerts", []))})
        for a in row.get("alerts", []):
            events.append({"ts": row.get("timestamp"), "type": "alert", "alert_id": a.get("id"), "severity": a.get("severity"), "title": a.get("title")})

    triage = load_triage(data_dir)
    for item in triage.get("items", []):
        for h in item.get("history", []):
            events.append({"ts": h.get("ts"), "type": "triage", "alert_id": item.get("alert_id"), "status": h.get("status"), "owner": h.get("owner", "")})

    def key(x: dict) -> float:
        try:
            return datetime.fromisoformat(x.get("ts", "1970-01-01T00:00:00+00:00")).timestamp()
        except Exception:
            return 0.0

    events.sort(key=key)
    return events
