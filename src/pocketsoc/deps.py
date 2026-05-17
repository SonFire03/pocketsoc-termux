from __future__ import annotations

from pathlib import Path


def verify_lock(lockfile: Path) -> dict:
    if not lockfile.exists():
        return {"ok": False, "error": "lockfile missing"}
    lines = [ln.strip() for ln in lockfile.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    bad = [ln for ln in lines if "==" not in ln]
    return {"ok": len(bad) == 0, "entries": len(lines), "invalid": bad}
