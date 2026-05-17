from __future__ import annotations

import re
from copy import deepcopy


_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _redact_text(text: str) -> str:
    text = _IPV4_PATTERN.sub("<redacted-ip>", text)
    text = re.sub(r"\b([0-9]{2,6})\b", "<redacted-num>", text)
    return text


def redact_scan_data(scan: dict, alerts: dict) -> tuple[dict, dict]:
    safe_scan = deepcopy(scan)
    safe_alerts = deepcopy(alerts)

    for check in safe_scan.get("checks", []):
        details = check.get("details", {})
        for key in ("address", "routes", "error", "route_error", "address_error"):
            if isinstance(details.get(key), str):
                details[key] = _redact_text(details[key])
        if isinstance(details.get("processes"), list):
            details["processes"] = [_redact_text(p) for p in details["processes"]]
        if isinstance(details.get("ports"), list):
            details["ports"] = [_redact_text(p) for p in details["ports"]]

    for alert in safe_alerts.get("alerts", []):
        if isinstance(alert.get("description"), str):
            alert["description"] = _redact_text(alert["description"])

    return safe_scan, safe_alerts
