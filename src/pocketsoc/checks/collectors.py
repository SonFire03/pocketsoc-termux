from __future__ import annotations

import shutil
from pathlib import Path

from ..config import ThresholdConfig
from ..models import CheckResult
from ..system import command_exists, parse_json, run_command


def check_storage_usage(thresholds: ThresholdConfig, path: Path | None = None) -> CheckResult:
    target = path or Path.home()
    usage = shutil.disk_usage(target)

    total_gb = usage.total / (1024**3)
    used_gb = usage.used / (1024**3)
    free_gb = usage.free / (1024**3)
    used_pct = (usage.used / usage.total) * 100 if usage.total else 0

    status = "ok"
    if used_pct >= thresholds.storage_critical_pct:
        status = "critical"
    elif used_pct >= thresholds.storage_warning_pct:
        status = "warning"

    return CheckResult(
        name="storage_usage",
        status=status,
        summary=f"{used_pct:.1f}% used on {target}",
        details={
            "path": str(target),
            "total_gb": round(total_gb, 2),
            "used_gb": round(used_gb, 2),
            "free_gb": round(free_gb, 2),
            "used_pct": round(used_pct, 2),
        },
    )


def check_battery_info(thresholds: ThresholdConfig) -> CheckResult:
    if not command_exists("termux-battery-status"):
        return CheckResult("battery_info", "info", "termux-battery-status not available", {"available": False})

    ok, output = run_command(["termux-battery-status"])
    if not ok:
        return CheckResult("battery_info", "warning", "failed to collect battery info", {"available": True, "error": output})

    parsed_ok, payload = parse_json(output)
    if not parsed_ok:
        return CheckResult("battery_info", "warning", "invalid battery JSON payload", {"available": True, **payload})

    pct = payload.get("percentage")
    status = "ok"
    if isinstance(pct, (int, float)):
        if pct <= thresholds.battery_critical_pct:
            status = "critical"
        elif pct <= thresholds.battery_warning_pct:
            status = "warning"

    return CheckResult("battery_info", status, f"battery {pct}%" if pct is not None else "battery information collected", {"available": True, **payload})


def check_network_info() -> CheckResult:
    if command_exists("ip"):
        ok_addr, addr = run_command(["ip", "-brief", "address"])
        ok_route, route = run_command(["ip", "route"])
    elif command_exists("ifconfig"):
        ok_addr, addr = run_command(["ifconfig"])
        ok_route, route = run_command(["route", "-n"] if command_exists("route") else ["echo", ""])
    else:
        return CheckResult("network_info", "info", "ip/ifconfig command not available", {"available": False})

    if not ok_addr and not ok_route:
        return CheckResult(
            "network_info",
            "warning",
            "failed to collect network info",
            {"available": True, "address_error": addr, "route_error": route},
        )

    return CheckResult(
        "network_info",
        "ok",
        "network interfaces and routes collected",
        {
            "available": True,
            "address": addr if ok_addr else "",
            "routes": route if ok_route else "",
            "address_error": "" if ok_addr else addr,
            "route_error": "" if ok_route else route,
        },
    )


def check_listening_ports(thresholds: ThresholdConfig) -> CheckResult:
    cmd: list[str] | None = None
    source = ""

    if command_exists("ss"):
        cmd = ["ss", "-tuln"]
        source = "ss"
    elif command_exists("netstat"):
        cmd = ["netstat", "-tuln"]
        source = "netstat"

    if cmd is None:
        return CheckResult("listening_ports", "info", "ss/netstat not available", {"available": False, "ports": []})

    ok, output = run_command(cmd)
    if not ok:
        return CheckResult(
            "listening_ports",
            "warning",
            "failed to collect listening ports",
            {"available": True, "source": source, "error": output, "ports": []},
        )

    lines = [line for line in output.splitlines() if line.strip()]
    if lines and ("Netid" in lines[0] or "Proto" in lines[0]):
        lines = lines[1:]

    status = "warning" if len(lines) > thresholds.listening_ports_warning_count else "ok"
    return CheckResult(
        "listening_ports",
        status,
        f"{len(lines)} listening entries found",
        {"available": True, "source": source, "ports": lines},
    )


def check_running_processes(thresholds: ThresholdConfig) -> CheckResult:
    if not command_exists("ps"):
        return CheckResult("running_processes", "info", "ps command not available", {"available": False, "count": 0, "processes": []})

    variants = [["ps", "-A", "-o", "pid,ppid,comm"], ["ps", "-ef"], ["ps"]]
    ok = False
    output = ""
    for cmd in variants:
        ok, output = run_command(cmd)
        if ok:
            break

    if not ok:
        return CheckResult("running_processes", "warning", "failed to collect running processes", {"available": True, "error": output, "count": 0, "processes": []})

    lines = [line for line in output.splitlines() if line.strip()]
    if lines and any(head in lines[0] for head in ("PID", "UID", "USER")):
        lines = lines[1:]

    status = "warning" if len(lines) > thresholds.process_warning_count else "ok"
    return CheckResult("running_processes", status, f"{len(lines)} processes observed", {"available": True, "count": len(lines), "processes": lines[:100]})
