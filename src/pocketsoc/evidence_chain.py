from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .output.files import ensure_data_dir

CHAIN_FILE = "evidence-chain.jsonl"


def _hash_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def append_evidence(event_type: str, ref: str, digest: str, data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    p = root / CHAIN_FILE
    prev_hash = ""
    if p.exists():
        lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            try:
                prev = json.loads(lines[-1])
                prev_hash = prev.get("chain_hash", "")
            except Exception:
                prev_hash = ""

    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "ref": ref,
        "digest": digest,
        "prev_hash": prev_hash,
    }
    row["chain_hash"] = _hash_text(json.dumps(row, sort_keys=True))
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


def verify_chain(data_dir: Path | None = None) -> dict:
    root = ensure_data_dir(data_dir)
    p = root / CHAIN_FILE
    if not p.exists():
        return {"ok": True, "items": 0}
    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    prev = ""
    for idx, ln in enumerate(lines, start=1):
        row = json.loads(ln)
        if row.get("prev_hash", "") != prev:
            return {"ok": False, "error": f"broken prev_hash at line {idx}"}
        ch = row.pop("chain_hash", "")
        computed = _hash_text(json.dumps(row, sort_keys=True))
        if ch != computed:
            return {"ok": False, "error": f"invalid hash at line {idx}"}
        prev = ch
    return {"ok": True, "items": len(lines)}
