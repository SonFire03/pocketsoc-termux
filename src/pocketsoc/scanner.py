from __future__ import annotations

from .alerts import build_alerts, calculate_risk_score
from .checks.collectors import (
    check_battery_info,
    check_listening_ports,
    check_network_info,
    check_running_processes,
    check_storage_usage,
)
from .config import ThresholdConfig
from .models import ScanResult, utc_now_iso


def run_scan(thresholds: ThresholdConfig) -> ScanResult:
    checks = [
        check_storage_usage(thresholds),
        check_battery_info(thresholds),
        check_network_info(),
        check_listening_ports(thresholds),
        check_running_processes(thresholds),
    ]
    alerts = build_alerts(checks, thresholds)
    return ScanResult(timestamp=utc_now_iso(), checks=checks, alerts=alerts, risk_score=calculate_risk_score(alerts))
