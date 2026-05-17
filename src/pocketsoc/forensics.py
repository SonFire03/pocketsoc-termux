from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .integrity import sign_payload
from .system import command_exists, run_command


def build_forensics_snapshot(data_dir: Path) -> Path:
    root = Path(data_dir)
    out = root / f"forensics-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"

    payload = {"timestamp": datetime.utcnow().isoformat() + "Z", "processes": [], "sockets": [], "startup_files": {}}

    if command_exists("ps"):
        ok, txt = run_command(["ps", "-A", "-o", "pid,ppid,comm"])
        if ok:
            payload["processes"] = txt.splitlines()[:300]
    if command_exists("ss"):
        ok, txt = run_command(["ss", "-tun"])
        if ok:
            payload["sockets"] = txt.splitlines()[:300]

    for name in [".bashrc", ".zshrc", ".profile"]:
        p = Path.home() / name
        if p.exists():
            payload["startup_files"][name] = p.read_text(encoding="utf-8", errors="ignore")[:4000]

    raw = json.dumps(payload, indent=2)
    out.write_text(raw, encoding="utf-8")
    out.with_suffix(out.suffix + ".sig").write_text(sign_payload(raw, root), encoding="utf-8")
    return out
