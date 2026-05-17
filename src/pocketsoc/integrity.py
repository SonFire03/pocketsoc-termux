from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path


def _root(data_dir: Path | None = None) -> Path:
    if data_dir is None:
        return Path.home() / ".pocketsoc"
    return data_dir


def _key_path(data_dir: Path | None = None) -> Path:
    root = _root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root / "integrity.key"


def get_or_create_key(data_dir: Path | None = None) -> bytes:
    p = _key_path(data_dir)
    if p.exists():
        return p.read_bytes()
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    return key


def sign_payload(payload: str, data_dir: Path | None = None) -> str:
    key = get_or_create_key(data_dir)
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_payload(payload: str, signature: str, data_dir: Path | None = None) -> bool:
    expected = sign_payload(payload, data_dir)
    return hmac.compare_digest(expected, signature)
