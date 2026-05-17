from pocketsoc.alerts import build_alerts, calculate_risk_score
from pocketsoc.config import ThresholdConfig
from pocketsoc.models import CheckResult


def test_storage_alert_triggers_on_high_usage() -> None:
    checks = [CheckResult(name="storage_usage", status="critical", summary="99% used", details={"used_pct": 99.0})]
    alerts = build_alerts(checks, ThresholdConfig())
    assert alerts
    assert alerts[0].id == "ALERT-STORAGE-CRITICAL"


def test_risk_score_computation() -> None:
    checks = [
        CheckResult(name="storage_usage", status="critical", summary="99% used", details={"used_pct": 99.0}),
        CheckResult(name="battery_info", status="critical", summary="battery 9%", details={"percentage": 9}),
    ]
    alerts = build_alerts(checks, ThresholdConfig())
    assert calculate_risk_score(alerts) >= 8
