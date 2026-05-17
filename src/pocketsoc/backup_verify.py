from __future__ import annotations

from pathlib import Path

from .output.files import ensure_data_dir


def verify_backup(data_dir=None) -> dict:
    root = ensure_data_dir(data_dir)
    b = root / "config-backup"
    if not b.exists():
        return {"ok": False, "error": "backup folder missing"}
    required = ["config.json", "rules.json", "policy.json"]
    present = [name for name in required if (b / name).exists()]
    return {"ok": len(present) > 0, "present": present, "missing": [x for x in required if x not in present]}
