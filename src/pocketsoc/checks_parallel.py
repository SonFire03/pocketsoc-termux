from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

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
from .config import ThresholdConfig
from .models import CheckResult


def run_checks_parallel(thresholds: ThresholdConfig, profile: str) -> list[CheckResult]:
    jobs = [
        lambda: check_storage_usage(thresholds),
        lambda: check_battery_info(thresholds),
        check_network_info,
        lambda: check_listening_ports(thresholds),
        lambda: check_running_processes(thresholds),
        check_app_inventory,
    ]
    if profile in ("standard", "deep"):
        jobs.extend([check_sensitive_permissions, lambda: check_package_hygiene(thresholds), check_local_persistence])
    if profile == "deep":
        jobs.extend([check_outbound_connections, check_binary_integrity])

    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as ex:
        return [f.result() for f in [ex.submit(job) for job in jobs]]
