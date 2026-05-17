from __future__ import annotations

from pathlib import Path

from .output.files import ensure_data_dir


def write_web_ui(data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / "webui.html"
    target.write_text(
        """<!doctype html><html><head><meta charset='utf-8'><title>PocketSOC UI</title></head>
<body><h1>PocketSOC Local UI</h1><p>Use API endpoints: /health /last-scan /alerts /trends</p></body></html>""",
        encoding="utf-8",
    )
    return target
