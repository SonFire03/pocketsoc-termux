from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .output.files import load_alerts, load_last_scan, load_scan_history


class _Handler(BaseHTTPRequestHandler):
    data_dir: Path | None = None

    def _auth_ok(self) -> bool:
        token = os.getenv("POCKETSOC_API_TOKEN", "")
        if not token:
            return True
        return self.headers.get("X-PocketSOC-Token", "") == token

    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth_ok():
            self._send({"error": "unauthorized"}, 401)
            return
        if self.path == "/health":
            self._send({"ok": True})
            return
        if self.path == "/last-scan":
            self._send(load_last_scan(self.data_dir))
            return
        if self.path == "/alerts":
            self._send(load_alerts(self.data_dir))
            return
        if self.path == "/trends":
            self._send({"items": load_scan_history(self.data_dir)[-50:]})
            return
        self._send({"error": "not found"}, 404)


def serve_api(host: str, port: int, data_dir: Path | None = None) -> None:
    _Handler.data_dir = data_dir
    HTTPServer((host, port), _Handler).serve_forever()
