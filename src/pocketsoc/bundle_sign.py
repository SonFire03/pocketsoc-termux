from __future__ import annotations

from pathlib import Path

from .integrity import sign_payload, verify_payload


def sign_bundle(bundle_path: Path, data_dir: Path | None = None) -> Path:
    raw = bundle_path.read_bytes()
    sig = sign_payload(raw.hex(), data_dir)
    sig_path = bundle_path.with_suffix(bundle_path.suffix + ".sig")
    sig_path.write_text(sig, encoding="utf-8")
    return sig_path


def verify_bundle(bundle_path: Path, data_dir: Path | None = None) -> bool:
    sig_path = bundle_path.with_suffix(bundle_path.suffix + ".sig")
    if not sig_path.exists():
        return False
    raw = bundle_path.read_bytes()
    sig = sig_path.read_text(encoding="utf-8").strip()
    return verify_payload(raw.hex(), sig, data_dir)
