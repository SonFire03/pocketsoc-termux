from __future__ import annotations

from .output.files import load_last_scan


def explain_alert(alert_id: str, data_dir=None) -> dict:
    scan = load_last_scan(data_dir)
    for alert in scan.get("alerts", []):
        if alert.get("id") == alert_id:
            src = alert.get("source_check", "unknown")
            check = next((c for c in scan.get("checks", []) if c.get("name") == src), None)
            return {
                "found": True,
                "alert": alert,
                "source_check": check,
                "explanation": f"Alert {alert_id} comes from check '{src}' with summary '{check.get('summary') if check else 'n/a'}'.",
            }
    return {"found": False, "error": f"alert {alert_id} not found"}
