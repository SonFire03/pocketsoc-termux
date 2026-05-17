from __future__ import annotations

from pathlib import Path

from .config import write_default_config
from .rules import write_default_rules


def run_autofix_safe(data_dir: Path | None = None) -> dict:
    cfg = write_default_config(data_dir, force=False)
    rules = write_default_rules(data_dir, force=False)
    return {"fixed": [str(cfg), str(rules)], "notes": ["Created missing config/rules if absent."]}
