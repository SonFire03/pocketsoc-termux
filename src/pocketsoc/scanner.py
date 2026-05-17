from __future__ import annotations

from .alerts import build_alerts, calculate_risk_score
from .checks.collectors import (
    check_battery_info,
    check_binary_integrity,
    check_listening_ports,
    check_local_persistence,
    check_network_info,
    check_outbound_connections,
    check_package_hygiene,
    check_running_processes,
    check_sensitive_permissions,
    check_storage_usage,
)
from .config import ThresholdConfig
from .models import ScanResult, utc_now_iso
from .rules import apply_custom_rules, load_rules


def run_scan(thresholds: ThresholdConfig, profile: str = "standard", rules_data_dir=None) -> ScanResult:
    checks = [check_storage_usage(thresholds), check_battery_info(thresholds), check_network_info(), check_listening_ports(thresholds), check_running_processes(thresholds)]

    if profile in ("standard", "deep"):
        checks.extend([check_sensitive_permissions(), check_package_hygiene(thresholds), check_local_persistence()])

    if profile == "deep":
        checks.extend([check_outbound_connections(), check_binary_integrity()])

    alerts = build_alerts(checks, thresholds)
    custom = apply_custom_rules(checks, load_rules(rules_data_dir))
    alerts.extend(custom)

    risk_score = calculate_risk_score(alerts)
    return ScanResult(timestamp=utc_now_iso(), checks=checks, alerts=alerts, risk_score=risk_score)
