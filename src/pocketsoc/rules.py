from __future__ import annotations

import json
import re
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
        {"id": "RULE-PROCESS-COUNT-HIGH", "logic": "AND", "conditions": [{"check": "running_processes", "detail_key": "count", "op": ">=", "value": 350}], "severity": "medium", "title": "Unusually high process count"},
        {"id": "RULE-STARTUP-REGEX", "logic": "AND", "conditions": [{"check": "local_persistence", "detail_key": "findings", "regex": "(curl|wget|nc)"}], "severity": "medium", "title": "Suspicious startup regex matched"},
    ]
    target.write_text(json.dumps(defaults, indent=2) + "\n", encoding="utf-8")
    return target


def _cmp(left: float, op: str, right: float) -> bool:
    return {">=": left >= right, ">": left > right, "<=": left <= right, "<": left < right, "==": left == right}.get(op, False)


def _eval_condition(check: CheckResult, cond: dict) -> bool:
    key = str(cond.get("detail_key", ""))
    data = check.details.get(key)
    if "regex" in cond and isinstance(data, list):
        pattern = re.compile(str(cond["regex"]), re.IGNORECASE)
        return any(pattern.search(str(item)) for item in data)
    if "regex" in cond and isinstance(data, str):
        return re.search(str(cond["regex"]), data, flags=re.IGNORECASE) is not None
    if isinstance(data, (int, float)) and isinstance(cond.get("value"), (int, float)):
        return _cmp(float(data), str(cond.get("op", "")), float(cond["value"]))
    return False


def apply_custom_rules(checks: list[CheckResult], rules: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    by_name = {c.name: c for c in checks}
    for rule in rules:
        logic = str(rule.get("logic", "AND")).upper()
        conditions = rule.get("conditions", [])
        if not isinstance(conditions, list) or not conditions:
            continue
        results = []
        for cond in conditions:
            check = by_name.get(str(cond.get("check", "")))
            results.append(_eval_condition(check, cond) if check else False)
        matched = all(results) if logic == "AND" else any(results)
        if matched:
            alerts.append(Alert(id=str(rule.get("id", "RULE-CUSTOM")), severity=str(rule.get("severity", "low")), title=str(rule.get("title", "Custom rule matched")), description=f"rule {rule.get('id', 'RULE-CUSTOM')} matched", source_check="custom_rules"))
    return alerts
