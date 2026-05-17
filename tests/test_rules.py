from pocketsoc.models import CheckResult
from pocketsoc.rules import apply_custom_rules


def test_rules_v2_regex_and_logic() -> None:
    checks = [CheckResult(name="local_persistence", status="warning", summary="1", details={"findings": ["curl http://x"]})]
    rules = [{"id": "R1", "logic": "AND", "conditions": [{"check": "local_persistence", "detail_key": "findings", "regex": "curl"}], "severity": "medium", "title": "match"}]
    alerts = apply_custom_rules(checks, rules)
    assert alerts and alerts[0].id == "R1"
