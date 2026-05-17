from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .output.files import ensure_data_dir

TRIAGE_FILE = "triage-board.json"

DEFAULT_SLA_HOURS = {
    "high": 4,
    "medium": 24,
    "low": 72,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _path(data_dir: Path | None = None) -> Path:
    return ensure_data_dir(data_dir) / TRIAGE_FILE


def load_triage(data_dir: Path | None = None) -> dict:
    p = _path(data_dir)
    if not p.exists():
        return {"items": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"items": []}
    if not isinstance(data, dict) or "items" not in data:
        return {"items": []}
    return data


def save_triage(payload: dict, data_dir: Path | None = None) -> Path:
    p = _path(data_dir)
    p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return p


def upsert_alert_state(alert_id: str, severity: str, status: str = "new", owner: str = "", comment: str = "", data_dir: Path | None = None) -> dict:
    board = load_triage(data_dir)
    items = board["items"]
    now = _now().isoformat()
    due = (_now() + timedelta(hours=DEFAULT_SLA_HOURS.get(severity, 24))).isoformat()

    existing = next((x for x in items if x.get("alert_id") == alert_id), None)
    if existing is None:
        entry = {
            "alert_id": alert_id,
            "severity": severity,
            "status": status,
            "owner": owner,
            "comment": comment,
            "created_at": now,
            "updated_at": now,
            "due_at": due,
            "history": [{"ts": now, "status": status, "owner": owner, "comment": comment}],
        }
        items.append(entry)
        save_triage(board, data_dir)
        return entry

    existing["status"] = status or existing.get("status", "new")
    if owner:
        existing["owner"] = owner
    if comment:
        existing["comment"] = comment
    existing["updated_at"] = now
    existing.setdefault("history", []).append({"ts": now, "status": existing["status"], "owner": existing.get("owner", ""), "comment": comment})
    save_triage(board, data_dir)
    return existing


def compute_overdue(data_dir: Path | None = None) -> list[dict]:
    board = load_triage(data_dir)
    now = _now()
    out = []
    for item in board.get("items", []):
        if item.get("status") in {"mitigated", "false_positive"}:
            continue
        try:
            due = datetime.fromisoformat(item.get("due_at"))
        except Exception:
            continue
        if due < now:
            out.append(item)
    return out
