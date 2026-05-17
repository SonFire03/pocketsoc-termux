from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .output.files import ensure_data_dir

SUPPRESS_FILE = "suppressions.json"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def load_suppressions(data_dir: Path | None = None) -> list[dict]:
    root = ensure_data_dir(data_dir)
    p = root / SUPPRESS_FILE
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    return data if isinstance(data, list) else []


def save_suppressions(items: list[dict], data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    p = root / SUPPRESS_FILE
    p.write_text(json.dumps(items, indent=2) + "\n", encoding="utf-8")
    return p


def add_suppression(rule: dict, data_dir: Path | None = None) -> Path:
    items = load_suppressions(data_dir)
    items.append(rule)
    return save_suppressions(items, data_dir)


def _active(rule: dict) -> bool:
    exp = rule.get("expires_at")
    if not exp:
        return True
    try:
        return datetime.fromisoformat(exp) > _now()
    except Exception:
        return True


def filter_alerts(alerts: list[dict], data_dir: Path | None = None) -> list[dict]:
    rules = [r for r in load_suppressions(data_dir) if _active(r)]
    out = []
    for a in alerts:
        text = f"{a.get('id','')} {a.get('source_check','')} {a.get('title','')} {a.get('description','')}".lower()
        blocked = False
        for r in rules:
            patt = str(r.get("pattern", "")).lower()
            if patt and patt in text:
                blocked = True
                break
        if not blocked:
            out.append(a)
    return out
