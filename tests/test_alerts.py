from pocketsoc.alerts import build_alerts
from pocketsoc.config import ThresholdConfig
from pocketsoc.models import CheckResult


def test_storage_alert_triggers_on_high_usage() -> None:
    checks = [
        CheckResult(
            name="storage_usage",
            status="critical",
            summary="99% used",
            details={"used_pct": 99.0},
        )
    ]
    alerts = build_alerts(checks, ThresholdConfig())
    assert alerts
    assert alerts[0].id == "ALERT-STORAGE-CRITICAL"
