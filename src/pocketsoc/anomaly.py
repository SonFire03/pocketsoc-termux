from __future__ import annotations

import statistics


def detect_stat_anomalies(history: list[dict], latest: dict) -> list[str]:
    if len(history) < 5:
        return []

    last = history[-30:]
    risks = [x.get("risk_score", 0) for x in last]
    alerts = [len(x.get("alerts", [])) for x in last]

    findings: list[str] = []
    for name, arr, val in [
        ("risk_score", risks, latest.get("risk_score", 0)),
        ("alert_count", alerts, len(latest.get("alerts", []))),
    ]:
        mean = statistics.mean(arr)
        stdev = statistics.pstdev(arr) or 1.0
        z = (val - mean) / stdev
        if z >= 2.5:
            findings.append(f"{name} anomaly: z={z:.2f}, value={val}, mean={mean:.2f}")
    return findings
