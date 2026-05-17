from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from .output.files import ensure_data_dir


def build_incident_bundle(data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    out = root / f"incident-bundle-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    with ZipFile(out, "w", compression=ZIP_DEFLATED) as zf:
        for name in ["last_scan.json", "alerts.json", "pocketsoc-report.md", "scan-history.jsonl", "baseline.json"]:
            p = root / name
            if p.exists():
                zf.write(p, arcname=name)
    return out
