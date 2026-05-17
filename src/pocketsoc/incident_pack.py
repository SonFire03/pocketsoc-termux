from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from .evidence_chain import append_evidence
from .output.files import ensure_data_dir
from .timeline import build_timeline
from .triage import load_triage


def export_incident_pack(data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    out = root / f"incident-pack-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    with ZipFile(out, "w", compression=ZIP_DEFLATED) as zf:
        scan = root / "last_scan.json"
        alerts = root / "alerts.json"
        if scan.exists():
            zf.write(scan, arcname="last_scan.json")
        if alerts.exists():
            zf.write(alerts, arcname="alerts.json")

        tl = build_timeline(root)
        triage = load_triage(root)
        tmp_tl = root / "_incident_timeline.json"
        tmp_tr = root / "_incident_triage.json"
        tmp_tl.write_text(json.dumps(tl, indent=2), encoding="utf-8")
        tmp_tr.write_text(json.dumps(triage, indent=2), encoding="utf-8")
        zf.write(tmp_tl, arcname="timeline.json")
        zf.write(tmp_tr, arcname="triage-board.json")
        tmp_tl.unlink(missing_ok=True)
        tmp_tr.unlink(missing_ok=True)

    append_evidence("incident_pack", out.name, out.read_bytes().hex()[:64], root)
    return out
