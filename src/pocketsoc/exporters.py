from __future__ import annotations

import json
from pathlib import Path

from .output.files import ensure_data_dir, load_alerts


def export_siem(data_dir: Path | None = None, fmt: str = "syslog-json") -> Path:
    root = ensure_data_dir(data_dir)
    payload = load_alerts(root)
    target = root / ("siem.cef" if fmt == "cef" else "siem.ndjson")

    if fmt == "cef":
        lines = []
        for a in payload.get("alerts", []):
            sev = {"low": 3, "medium": 6, "high": 9}.get(a.get("severity", "low"), 1)
            lines.append(f"CEF:0|PocketSOC|PocketSOC|1.0|{a.get('id','ALERT')}|{a.get('title','Alert')}|{sev}|cs1={a.get('source_check','unknown')}")
        target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    else:
        with target.open("w", encoding="utf-8") as fh:
            for a in payload.get("alerts", []):
                fh.write(json.dumps({"source": "pocketsoc", "alert": a}) + "\n")
    return target
