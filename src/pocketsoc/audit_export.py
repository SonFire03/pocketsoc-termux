from __future__ import annotations

import csv
import json
from pathlib import Path

from .output.files import ensure_data_dir


def export_audit(data_dir=None, fmt: str = "json") -> Path:
    root = ensure_data_dir(data_dir)
    src = root / "api-audit.log"
    lines = []
    if src.exists():
        for ln in src.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                lines.append(json.loads(ln))
            except Exception:
                continue

    if fmt == "csv":
        out = root / "api-audit.csv"
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["timestamp", "endpoint", "status"])
            w.writeheader()
            for row in lines:
                w.writerow({"timestamp": row.get("timestamp"), "endpoint": row.get("endpoint"), "status": row.get("status")})
        return out

    out = root / "api-audit-export.json"
    out.write_text(json.dumps(lines, indent=2) + "\n", encoding="utf-8")
    return out
