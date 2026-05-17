from __future__ import annotations

from pathlib import Path


def run_quality_gate(repo_root: Path) -> dict:
    checks = {
        "changelog_exists": (repo_root / "CHANGELOG.md").exists(),
        "readme_exists": (repo_root / "README.md").exists(),
        "pyproject_exists": (repo_root / "pyproject.toml").exists(),
    }
    checks["ok"] = all(v for k, v in checks.items() if k != "ok")
    return checks
