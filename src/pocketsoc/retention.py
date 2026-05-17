from __future__ import annotations

import json
from pathlib import Path

from .output.files import ensure_data_dir


def write_retention_policy(data_dir=None, force: bool = False) -> Path:
    root = ensure_data_dir(data_dir)
    p = root / "retention.json"
    if p.exists() and not force:
        return p
    p.write_text(json.dumps({"history_days": 30, "audit_days": 30, "bundle_days": 14, "forensics_days": 14}, indent=2) + "\n", encoding="utf-8")
    return p


def load_retention_policy(data_dir=None) -> dict:
    root = ensure_data_dir(data_dir)
    p = root / "retention.json"
    if not p.exists():
        write_retention_policy(root)
    return json.loads(p.read_text(encoding="utf-8"))
