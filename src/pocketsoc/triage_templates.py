from __future__ import annotations

from .comment_templates import TEMPLATES
from .triage import upsert_alert_state


def apply_template(alert_id: str, severity: str, template_key: str, status: str = "investigating", owner: str = "", source_check: str = "", data_dir=None) -> dict:
    comment = TEMPLATES.get(template_key)
    if not comment:
        return {"error": f"unknown template {template_key}"}
    return upsert_alert_state(alert_id=alert_id, severity=severity, status=status, owner=owner, comment=comment, source_check=source_check, data_dir=data_dir)
