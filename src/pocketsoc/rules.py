from __future__ import annotations

import json
from pathlib import Path

from .models import Alert, CheckResult
from .output.files import ensure_data_dir


RULES_FILE = "rules.json"


def load_rules(data_dir: Path | None = None) -> list[dict]:
    root = ensure_data_dir(data_dir)
    target = root / RULES_FILE
    if not target.exists():
        return []
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return payload if isinstance(payload, list) else []


def write_default_rules(data_dir: Path | None = None, force: bool = False) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / RULES_FILE
    if target.exists() and not force:
        return target
    defaults = [
        {
            "id": "RULE-PROCESS-COUNT-HIGH",
            "check": "running_processes",
            "detail_key": "count",
            "op": ">=",
            "value": 350,
            "severity": "medium",
            "title": "Unusually high process count",
        }
    ]
    target.write_text(json.dumps(defaults, indent=2) + "\n", encoding="utf-8")
    return target


def _compare(left: float, op: str, right: float) -> bool:
    if op == ">=":
        return left >= right
    if op == ">":
        return left > right
    if op == "<=":
        return left <= right
    if op == "<":
        return left < right
    if op == "==":
        return left == right
    return False


def apply_custom_rules(checks: list[CheckResult], rules: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    by_name = {c.name: c for c in checks}
    for rule in rules:
        check_name = str(rule.get("check", ""))
        check = by_name.get(check_name)
        if not check:
            continue
        key = str(rule.get("detail_key", ""))
        op = str(rule.get("op", ""))
        val = rule.get("value")
        data = check.details.get(key)
        if not isinstance(data, (int, float)) or not isinstance(val, (int, float)):
            continue
        if _compare(float(data), op, float(val)):
            alerts.append(
                Alert(
                    id=str(rule.get("id", "RULE-CUSTOM")),
                    severity=str(rule.get("severity", "low")),
                    title=str(rule.get("title", "Custom rule matched")),
                    description=f"{check_name}.{key}={data} {op} {val}",
                    source_check=check_name,
                )
            )
    return alerts
