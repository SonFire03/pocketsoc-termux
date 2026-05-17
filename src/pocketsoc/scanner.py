from __future__ import annotations

from pathlib import Path

from .alert_fatigue import suppress_repeated_alerts
from .alerts import build_alerts, calculate_risk_score
from .alerts_burst import detect_burst
from .anomaly import detect_stat_anomalies
from .checks.collectors import (
    check_app_inventory,
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
from .checks_parallel import run_checks_parallel
from .config import ThresholdConfig
from .models import Alert, ScanResult, utc_now_iso
from .plugins import load_plugin_checks
from .rules import apply_custom_rules, load_rules
from .scoring import category_scores


def _run_checks_serial(thresholds: ThresholdConfig, profile: str) -> list:
    checks = [check_storage_usage(thresholds), check_battery_info(thresholds), check_network_info(), check_listening_ports(thresholds), check_running_processes(thresholds), check_app_inventory()]
    if profile in ("standard", "deep"):
        checks.extend([check_sensitive_permissions(), check_package_hygiene(thresholds), check_local_persistence()])
    if profile == "deep":
        checks.extend([check_outbound_connections(), check_binary_integrity()])
    return checks


def run_scan(
    thresholds: ThresholdConfig,
    profile: str = "standard",
    rules_data_dir=None,
    history: list[dict] | None = None,
    since_last: bool = False,
    parallel: bool = False,
    timeout_seconds: int = 60,
    resource_profile: str = "balanced",
) -> ScanResult:
    _ = timeout_seconds
    if resource_profile == "low":
        parallel = False

    checks = run_checks_parallel(thresholds, profile) if parallel else _run_checks_serial(thresholds, profile)

    if rules_data_dir:
        checks.extend(load_plugin_checks(Path(rules_data_dir) / "checks.d"))

    alerts = build_alerts(checks, thresholds)
    alerts.extend(apply_custom_rules(checks, load_rules(rules_data_dir)))

    dict_alerts = [{"id": a.id, "severity": a.severity, "title": a.title, "description": a.description, "source_check": a.source_check} for a in alerts]
    dict_alerts = suppress_repeated_alerts(dict_alerts, history or [], cooldown_minutes=5)

    if since_last and history:
        last_ids = {a.get("id") for a in history[-1].get("alerts", [])}
        dict_alerts = [a for a in dict_alerts if a.get("id") not in last_ids]

    if detect_burst(history or []):
        dict_alerts.append({"id": "ALERT-BURST", "severity": "high", "title": "Alert burst detected", "description": "Rapid increase of alerts in short time window", "source_check": "history"})

    latest_stub = {"risk_score": 0, "alerts": dict_alerts}
    anomalies = detect_stat_anomalies(history or [], latest_stub)
    for idx, entry in enumerate(anomalies, start=1):
        dict_alerts.append({"id": f"ALERT-ANOMALY-{idx}", "severity": "medium", "title": "Statistical anomaly detected", "description": entry, "source_check": "history"})

    final_alerts = [Alert(**a) for a in dict_alerts]
    risk = calculate_risk_score(final_alerts)
    result = ScanResult(timestamp=utc_now_iso(), checks=checks, alerts=final_alerts, risk_score=risk)
    setattr(result, "category_scores", category_scores(checks))
    return result
