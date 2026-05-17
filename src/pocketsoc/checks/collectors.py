from __future__ import annotations

import shutil
from pathlib import Path

from ..models import CheckResult
from ..system import command_exists, parse_json, run_command


def check_storage_usage(path: Path | None = None) -> CheckResult:
    target = path or Path.home()
    usage = shutil.disk_usage(target)

    total_gb = usage.total / (1024**3)
    used_gb = usage.used / (1024**3)
    free_gb = usage.free / (1024**3)
    used_pct = (usage.used / usage.total) * 100 if usage.total else 0

    status = "ok"
    if used_pct >= 95:
        status = "critical"
    elif used_pct >= 85:
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


def check_battery_info() -> CheckResult:
    if not command_exists("termux-battery-status"):
        return CheckResult(
            name="battery_info",
            status="info",
            summary="termux-battery-status not available",
            details={"available": False},
        )

    ok, output = run_command(["termux-battery-status"])
    if not ok:
        return CheckResult(
            name="battery_info",
            status="warning",
            summary="failed to collect battery info",
            details={"available": True, "error": output},
        )

    parsed_ok, payload = parse_json(output)
    if not parsed_ok:
        return CheckResult(
            name="battery_info",
            status="warning",
            summary="invalid battery JSON payload",
            details={"available": True, **payload},
        )

    pct = payload.get("percentage")
    status = "ok"
    if isinstance(pct, (int, float)):
        if pct <= 10:
            status = "critical"
        elif pct <= 20:
            status = "warning"

    return CheckResult(
        name="battery_info",
        status=status,
        summary=f"battery {pct}%" if pct is not None else "battery information collected",
        details={"available": True, **payload},
    )


def check_network_info() -> CheckResult:
    if not command_exists("ip"):
        return CheckResult(
            name="network_info",
            status="info",
            summary="ip command not available",
            details={"available": False},
        )

    ok_addr, addr = run_command(["ip", "-brief", "address"])
    ok_route, route = run_command(["ip", "route"])

    if not ok_addr and not ok_route:
        return CheckResult(
            name="network_info",
            status="warning",
            summary="failed to collect network info",
            details={"available": True, "address_error": addr, "route_error": route},
        )

    return CheckResult(
        name="network_info",
        status="ok",
        summary="network interfaces and routes collected",
        details={
            "available": True,
            "address": addr if ok_addr else "",
            "routes": route if ok_route else "",
            "address_error": "" if ok_addr else addr,
            "route_error": "" if ok_route else route,
        },
    )


def check_listening_ports() -> CheckResult:
    cmd: list[str] | None = None
    source = ""

    if command_exists("ss"):
        cmd = ["ss", "-tuln"]
        source = "ss"
    elif command_exists("netstat"):
        cmd = ["netstat", "-tuln"]
        source = "netstat"

    if cmd is None:
        return CheckResult(
            name="listening_ports",
            status="info",
            summary="ss/netstat not available",
            details={"available": False, "ports": []},
        )

    ok, output = run_command(cmd)
    if not ok:
        return CheckResult(
            name="listening_ports",
            status="warning",
            summary="failed to collect listening ports",
            details={"available": True, "source": source, "error": output, "ports": []},
        )

    lines = [line for line in output.splitlines() if line.strip()]
    # Remove header when present.
    if lines and ("Netid" in lines[0] or "Proto" in lines[0]):
        lines = lines[1:]

    status = "ok"
    if len(lines) > 25:
        status = "warning"

    return CheckResult(
        name="listening_ports",
        status=status,
        summary=f"{len(lines)} listening entries found",
        details={"available": True, "source": source, "ports": lines},
    )


def check_running_processes() -> CheckResult:
    if not command_exists("ps"):
        return CheckResult(
            name="running_processes",
            status="info",
            summary="ps command not available",
            details={"available": False, "count": 0, "processes": []},
        )

    ok, output = run_command(["ps", "-A", "-o", "pid,ppid,comm"])
    if not ok:
        return CheckResult(
            name="running_processes",
            status="warning",
            summary="failed to collect running processes",
            details={"available": True, "error": output, "count": 0, "processes": []},
        )

    lines = [line for line in output.splitlines() if line.strip()]
    if lines and "PID" in lines[0]:
        lines = lines[1:]

    status = "ok"
    if len(lines) > 250:
        status = "warning"

    return CheckResult(
        name="running_processes",
        status=status,
        summary=f"{len(lines)} processes observed",
        details={"available": True, "count": len(lines), "processes": lines[:100]},
    )
