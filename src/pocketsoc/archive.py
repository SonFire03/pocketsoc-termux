from __future__ import annotations

import gzip
from datetime import datetime
from pathlib import Path

from .integrity import sign_payload
from .output.files import HISTORY_FILE, ensure_data_dir


def rotate_history_archive(data_dir: Path | None = None) -> Path | None:
    root = ensure_data_dir(data_dir)
    src = root / HISTORY_FILE
    if not src.exists() or src.stat().st_size == 0:
        return None
    arch = root / "archives"
    arch.mkdir(exist_ok=True)
    name = f"history-{datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl.gz"
    target = arch / name
    raw = src.read_bytes()
    with gzip.open(target, "wb") as fh:
        fh.write(raw)
    (arch / f"{name}.sig").write_text(sign_payload(raw.decode('utf-8', errors='ignore'), root), encoding="utf-8")
    src.write_text("", encoding="utf-8")
    return target
