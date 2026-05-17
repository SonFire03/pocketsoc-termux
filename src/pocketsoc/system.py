from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import DEFAULT_DATA_DIR_NAME


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(command: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        return False, f"command failed: {exc}"

    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
        return False, err

    return True, proc.stdout.strip()


def parse_json(text: str) -> tuple[bool, dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, {"error": f"invalid JSON: {exc}"}

    if not isinstance(data, dict):
        return False, {"error": "JSON payload is not an object"}

    return True, data


def default_data_dir() -> Path:
    return Path.home() / DEFAULT_DATA_DIR_NAME
