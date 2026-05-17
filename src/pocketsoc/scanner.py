from __future__ import annotations

from pathlib import Path

from .alert_fatigue import suppress_repeated_alerts
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
from .plugins import load_plugin_checks
from .rules import apply_custom_rules, load_rules


def run_scan(thresholds: ThresholdConfig, profile: str = "standard", rules_data_dir=None, history: list[dict] | None = None) -> ScanResult:
    checks = [check_storage_usage(thresholds), check_battery_info(thresholds), check_network_info(), check_listening_ports(thresholds), check_running_processes(thresholds)]
    if profile in ("standard", "deep"):
        checks.extend([check_sensitive_permissions(), check_package_hygiene(thresholds), check_local_persistence()])
    if profile == "deep":
        checks.extend([check_outbound_connections(), check_binary_integrity()])

    plugin_dir = (Path(rules_data_dir) / "checks.d") if rules_data_dir else None
    if plugin_dir is not None:
        checks.extend(load_plugin_checks(plugin_dir))

    alerts = build_alerts(checks, thresholds)
    alerts.extend(apply_custom_rules(checks, load_rules(rules_data_dir)))

    as_dict = [{"id": a.id, "severity": a.severity, "title": a.title, "description": a.description, "source_check": a.source_check} for a in alerts]
    filtered = suppress_repeated_alerts(as_dict, history or [], cooldown_minutes=5)

    from .models import Alert

    final_alerts = [Alert(**a) for a in filtered]
    return ScanResult(timestamp=utc_now_iso(), checks=checks, alerts=final_alerts, risk_score=calculate_risk_score(final_alerts))
