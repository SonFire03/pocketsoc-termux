from __future__ import annotations

import secrets
from pathlib import Path

from .output.files import ensure_data_dir


def rotate_api_token(data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    token_file = root / "api-token.txt"
    token = secrets.token_urlsafe(24)
    token_file.write_text(token + "\n", encoding="utf-8")
    return token_file
