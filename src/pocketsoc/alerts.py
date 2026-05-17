from __future__ import annotations

from .config import ThresholdConfig
from .models import Alert, CheckResult


CRITICAL_PORT_KEYWORDS = (":5555", ":23", ":21")
SUSPICIOUS_PROCESS_KEYWORDS = ("nc", "ncat", "socat")
SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 5}


def _dedupe_alerts(alerts: list[Alert]) -> list[Alert]:
    seen: set[tuple[str, str, str]] = set()
    result: list[Alert] = []
    for alert in alerts:
        key = (alert.id, alert.source_check, alert.description)
        if key in seen:
            continue
        seen.add(key)
        result.append(alert)
    return result


def calculate_risk_score(alerts: list[Alert]) -> int:
    return sum(SEVERITY_WEIGHT.get(a.severity, 0) for a in alerts)


def build_alerts(checks: list[CheckResult], thresholds: ThresholdConfig) -> list[Alert]:
    alerts: list[Alert] = []
    found_sensitive_port = False
    found_suspicious_proc = False

    for check in checks:
        if check.name == "storage_usage":
            used_pct = check.details.get("used_pct", 0)
            if isinstance(used_pct, (int, float)) and used_pct >= thresholds.storage_critical_pct:
                alerts.append(Alert("ALERT-STORAGE-CRITICAL", "high", "Storage almost full", f"Storage usage is {used_pct:.1f}%", check.name))

        if check.name == "battery_info":
            pct = check.details.get("percentage")
            if isinstance(pct, (int, float)) and pct <= thresholds.battery_critical_pct:
                alerts.append(Alert("ALERT-BATTERY-LOW", "medium", "Battery critically low", f"Battery is at {pct}%", check.name))

        if check.name == "listening_ports":
            ports = check.details.get("ports", [])
            if isinstance(ports, list):
                exposed = [p for p in ports if any(key in p for key in CRITICAL_PORT_KEYWORDS)]
                if exposed:
                    found_sensitive_port = True
                for entry in exposed:
                    alerts.append(Alert("ALERT-PORT-SENSITIVE", "medium", "Sensitive listening port detected", entry, check.name))

        if check.name == "running_processes":
            procs = check.details.get("processes", [])
            if isinstance(procs, list):
                for proc in procs:
                    pl = proc.lower()
                    if any(key in pl for key in SUSPICIOUS_PROCESS_KEYWORDS):
                        found_suspicious_proc = True
                        alerts.append(Alert("ALERT-PROC-SUSPICIOUS", "low", "Potentially risky process name", proc, check.name))

        if check.name == "sensitive_permissions" and check.status == "warning":
            alerts.append(Alert("ALERT-PERM-WEAK", "medium", "Weak permissions on sensitive files", check.summary, check.name))

        if check.name == "package_hygiene" and check.status == "warning":
            alerts.append(Alert("ALERT-PACKAGES-OUTDATED", "low", "Many outdated packages", check.summary, check.name))

        if check.name == "local_persistence" and check.status == "warning":
            alerts.append(Alert("ALERT-PERSISTENCE-SUSPECT", "medium", "Suspicious startup command found", check.summary, check.name))

    if found_sensitive_port and found_suspicious_proc:
        alerts.append(
            Alert(
                "ALERT-CORRELATED-EXPOSURE",
                "high",
                "Correlated network/process risk",
                "Sensitive listening port and suspicious process observed in same scan",
                "correlation",
            )
        )

    return _dedupe_alerts(alerts)
