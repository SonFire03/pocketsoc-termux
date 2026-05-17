from __future__ import annotations

import shutil
from pathlib import Path

from .output.files import ensure_data_dir


def backup_config(data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    backup = root / "config-backup"
    backup.mkdir(exist_ok=True)
    for name in ["config.json", "rules.json", "policy.json"]:
        src = root / name
        if src.exists():
            shutil.copy2(src, backup / name)
    return backup


def restore_config(data_dir: Path | None = None) -> list[str]:
    root = ensure_data_dir(data_dir)
    backup = root / "config-backup"
    restored: list[str] = []
    if not backup.exists():
        return restored
    for name in ["config.json", "rules.json", "policy.json"]:
        src = backup / name
        if src.exists():
            shutil.copy2(src, root / name)
            restored.append(name)
    return restored
