from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from .crypto_zip import encrypt_file
from .evidence_chain import append_evidence
from .output.files import ensure_data_dir
from .output.files import load_last_scan, load_alerts
from .redaction import redact_scan_data
from .timeline import build_timeline


def build_incident_bundle(data_dir: Path | None = None, redact: bool = False, encrypt_password: str = "") -> Path:
    root = ensure_data_dir(data_dir)
    out = root / f"incident-bundle-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    with ZipFile(out, "w", compression=ZIP_DEFLATED) as zf:
        scan = load_last_scan(root)
        alerts = load_alerts(root)
        if redact:
            scan, alerts = redact_scan_data(scan, alerts)
            tmp_scan = root / "_bundle_scan_redacted.json"
            tmp_alerts = root / "_bundle_alerts_redacted.json"
            tmp_scan.write_text(str(scan), encoding="utf-8")
            tmp_alerts.write_text(str(alerts), encoding="utf-8")
            zf.write(tmp_scan, arcname="last_scan_redacted.json")
            zf.write(tmp_alerts, arcname="alerts_redacted.json")
            tmp_scan.unlink(missing_ok=True)
            tmp_alerts.unlink(missing_ok=True)
        for name in ["last_scan.json", "alerts.json", "pocketsoc-report.md", "scan-history.jsonl", "baseline.json"]:
            p = root / name
            if p.exists():
                zf.write(p, arcname=name)

        tl = build_timeline(root)
        tmp_tl = root / "timeline.json"
        tmp_tl.write_text(str(tl), encoding="utf-8")
        zf.write(tmp_tl, arcname="timeline.json")
        tmp_tl.unlink(missing_ok=True)

    if encrypt_password:
        out = encrypt_file(out, encrypt_password)

    digest = out.read_bytes().hex()[:64]
    append_evidence("bundle", out.name, digest, root)
    return out
