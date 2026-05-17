from __future__ import annotations

from .alerts import build_alerts
from .checks.collectors import (
    check_battery_info,
    check_listening_ports,
    check_network_info,
    check_running_processes,
    check_storage_usage,
)
from .models import ScanResult, utc_now_iso


def run_scan() -> ScanResult:
    checks = [
        check_storage_usage(),
        check_battery_info(),
        check_network_info(),
        check_listening_ports(),
        check_running_processes(),
    ]
    alerts = build_alerts(checks)
    return ScanResult(timestamp=utc_now_iso(), checks=checks, alerts=alerts)
