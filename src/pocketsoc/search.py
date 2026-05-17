from __future__ import annotations

from datetime import datetime, timedelta

from .output.files import load_alerts, load_last_scan, load_scan_history
from .timeline import build_timeline
from .triage import load_triage


def _cutoff(since: str) -> float:
    n = 7
    if since.endswith("d"):
        n = int(since[:-1])
    return (datetime.utcnow() - timedelta(days=n)).timestamp()


def global_search(query: str, since: str = "7d", data_dir=None) -> dict:
    q = query.lower()
    c = _cutoff(since)
    out = {"alerts": [], "checks": [], "triage": [], "timeline": []}

    scan = load_last_scan(data_dir)
    for ch in scan.get("checks", []):
        if q in str(ch).lower():
            out["checks"].append(ch)

    for al in load_alerts(data_dir).get("alerts", []):
        if q in str(al).lower():
            out["alerts"].append(al)

    for tr in load_triage(data_dir).get("items", []):
        if q in str(tr).lower():
            out["triage"].append(tr)

    for ev in build_timeline(data_dir):
        try:
            ts = datetime.fromisoformat(ev.get("ts", "")).timestamp()
        except Exception:
            ts = 0
        if ts >= c and q in str(ev).lower():
            out["timeline"].append(ev)

    return out
