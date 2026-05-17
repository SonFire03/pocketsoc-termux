from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .data_quality import compute_data_quality
from .output.files import ensure_data_dir, load_alerts, load_last_scan, load_scan_history
from .triage import upsert_alert_state

START_TS = time.time()


class _Handler(BaseHTTPRequestHandler):
    data_dir: Path | None = None

    def _log(self, endpoint: str, status: int) -> None:
        root = ensure_data_dir(self.data_dir)
        p = root / "api-audit.log"
        row = {"timestamp": datetime.now(timezone.utc).isoformat(), "endpoint": endpoint, "status": status}
        p.write_text((p.read_text(encoding="utf-8") if p.exists() else "") + json.dumps(row) + "\n", encoding="utf-8")

    def _auth_ok(self) -> bool:
        token = os.getenv("POCKETSOC_API_TOKEN", "")
        if not token:
            return True
        return self.headers.get("X-PocketSOC-Token", "") == token

    def _send(self, payload: dict, status: int = 200, endpoint: str = "") -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._log(endpoint, status)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path

        if not self._auth_ok():
            self._send({"error": "unauthorized"}, 401, path)
            return

        if path == "/health":
            self._send({"ok": True}, 200, path)
            return
        if path == "/last-scan":
            self._send(load_last_scan(self.data_dir), 200, path)
            return
        if path == "/alerts":
            payload = load_alerts(self.data_dir)
            sev = qs.get("severity", [None])[0]
            lim = int(qs.get("limit", ["200"])[0])
            alerts = payload.get("alerts", [])
            if sev:
                alerts = [a for a in alerts if a.get("severity") == sev]
            payload["alerts"] = alerts[:lim]
            self._send(payload, 200, path)
            return
        if path == "/trends":
            items = load_scan_history(self.data_dir)
            lim = int(qs.get("limit", ["50"])[0])
            self._send({"items": items[-lim:]}, 200, path)
            return
        if path == "/metrics":
            scan = load_last_scan(self.data_dir)
            quality = compute_data_quality(scan.get("checks", [])) if scan else {"score": 0}
            self._send({"risk_score": scan.get("risk_score", 0), "alerts_count": len(scan.get("alerts", [])), "data_quality": quality.get("score", 0), "uptime_seconds": int(time.time() - START_TS)}, 200, path)
            return

        self._send({"error": "not found"}, 404, path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._auth_ok():
            self._send({"error": "unauthorized"}, 401, path)
            return

        if path == "/alert-state":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                payload = json.loads(raw)
            except Exception:
                self._send({"error": "invalid json"}, 400, path)
                return
            entry = upsert_alert_state(
                alert_id=str(payload.get("alert_id", "")),
                severity=str(payload.get("severity", "low")),
                status=str(payload.get("status", "new")),
                owner=str(payload.get("owner", "")),
                comment=str(payload.get("comment", "")),
                data_dir=self.data_dir,
            )
            self._send({"ok": True, "item": entry}, 200, path)
            return

        self._send({"error": "not found"}, 404, path)


def serve_api(host: str, port: int, data_dir: Path | None = None) -> None:
    _Handler.data_dir = data_dir
    HTTPServer((host, port), _Handler).serve_forever()
