from __future__ import annotations

from pathlib import Path

from .integrity import verify_payload


def verify_forensics_snapshot(snapshot_path: Path, data_dir: Path | None = None) -> bool:
    sig_path = snapshot_path.with_suffix(snapshot_path.suffix + ".sig")
    if not snapshot_path.exists() or not sig_path.exists():
        return False
    raw = snapshot_path.read_text(encoding="utf-8")
    sig = sig_path.read_text(encoding="utf-8").strip()
    return verify_payload(raw, sig, data_dir)
