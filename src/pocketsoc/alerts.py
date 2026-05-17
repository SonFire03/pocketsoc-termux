from __future__ import annotations

from .config import ThresholdConfig
from .models import Alert, CheckResult


CRITICAL_PORT_KEYWORDS = (":5555", ":23", ":21")
SUSPICIOUS_PROCESS_KEYWORDS = ("nc", "ncat", "socat")


def build_alerts(checks: list[CheckResult], thresholds: ThresholdConfig) -> list[Alert]:
    alerts: list[Alert] = []

    for check in checks:
        if check.name == "storage_usage":
            used_pct = check.details.get("used_pct", 0)
            if isinstance(used_pct, (int, float)) and used_pct >= thresholds.storage_critical_pct:
                alerts.append(
                    Alert(
                        id="ALERT-STORAGE-CRITICAL",
                        severity="high",
                        title="Storage almost full",
                        description=f"Storage usage is {used_pct:.1f}%",
                        source_check=check.name,
                    )
                )

        if check.name == "battery_info":
            pct = check.details.get("percentage")
            if isinstance(pct, (int, float)) and pct <= thresholds.battery_critical_pct:
                alerts.append(
                    Alert(
                        id="ALERT-BATTERY-LOW",
                        severity="medium",
                        title="Battery critically low",
                        description=f"Battery is at {pct}%",
                        source_check=check.name,
                    )
                )

        if check.name == "listening_ports":
            ports = check.details.get("ports", [])
            if isinstance(ports, list):
                exposed = [p for p in ports if any(key in p for key in CRITICAL_PORT_KEYWORDS)]
                for entry in exposed:
                    alerts.append(
                        Alert(
                            id="ALERT-PORT-SENSITIVE",
                            severity="medium",
                            title="Sensitive listening port detected",
                            description=entry,
                            source_check=check.name,
                        )
                    )

        if check.name == "running_processes":
            procs = check.details.get("processes", [])
            if isinstance(procs, list):
                for proc in procs:
                    pl = proc.lower()
                    if any(key in pl for key in SUSPICIOUS_PROCESS_KEYWORDS):
                        alerts.append(
                            Alert(
                                id="ALERT-PROC-SUSPICIOUS",
                                severity="low",
                                title="Potentially risky process name",
                                description=proc,
                                source_check=check.name,
                            )
                        )

    return alerts
