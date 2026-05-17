from __future__ import annotations

import importlib.util
from pathlib import Path

from .models import CheckResult


def load_plugin_checks(plugin_dir: Path) -> list[CheckResult]:
    checks: list[CheckResult] = []
    if not plugin_dir.exists():
        return checks
    for py in plugin_dir.glob("*.py"):
        spec = importlib.util.spec_from_file_location(py.stem, py)
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, "run_check"):
            try:
                res = mod.run_check()
                if isinstance(res, CheckResult):
                    checks.append(res)
            except Exception:
                continue
    return checks
