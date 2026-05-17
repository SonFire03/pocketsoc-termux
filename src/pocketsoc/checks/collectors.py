from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

from ..config import ThresholdConfig
from ..models import CheckResult
from ..system import command_exists, parse_json, run_command


SENSITIVE_PATHS = [
    Path.home() / ".ssh",
    Path.home() / ".bashrc",
    Path.home() / ".zshrc",
    Path.home() / ".profile",
]


def check_storage_usage(thresholds: ThresholdConfig, path: Path | None = None) -> CheckResult:
    target = path or Path.home()
    usage = shutil.disk_usage(target)
    used_pct = (usage.used / usage.total) * 100 if usage.total else 0
    status = "critical" if used_pct >= thresholds.storage_critical_pct else "warning" if used_pct >= thresholds.storage_warning_pct else "ok"
    return CheckResult("storage_usage", status, f"{used_pct:.1f}% used on {target}", {
        "path": str(target),
        "total_gb": round(usage.total / (1024**3), 2),
        "used_gb": round(usage.used / (1024**3), 2),
        "free_gb": round(usage.free / (1024**3), 2),
        "used_pct": round(used_pct, 2),
    })


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
        status = "critical" if pct <= thresholds.battery_critical_pct else "warning" if pct <= thresholds.battery_warning_pct else "ok"
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
        return CheckResult("network_info", "warning", "failed to collect network info", {"available": True, "address_error": addr, "route_error": route})
    return CheckResult("network_info", "ok", "network interfaces and routes collected", {
        "available": True,
        "address": addr if ok_addr else "",
        "routes": route if ok_route else "",
        "address_error": "" if ok_addr else addr,
        "route_error": "" if ok_route else route,
    })


def check_listening_ports(thresholds: ThresholdConfig) -> CheckResult:
    cmd: list[str] | None = ["ss", "-tuln"] if command_exists("ss") else ["netstat", "-tuln"] if command_exists("netstat") else None
    if cmd is None:
        return CheckResult("listening_ports", "info", "ss/netstat not available", {"available": False, "ports": []})
    ok, output = run_command(cmd)
    if not ok:
        return CheckResult("listening_ports", "warning", "failed to collect listening ports", {"available": True, "error": output, "ports": []})
    lines = [line for line in output.splitlines() if line.strip()]
    if lines and ("Netid" in lines[0] or "Proto" in lines[0]):
        lines = lines[1:]
    status = "warning" if len(lines) > thresholds.listening_ports_warning_count else "ok"
    return CheckResult("listening_ports", status, f"{len(lines)} listening entries found", {"available": True, "ports": lines})


def check_running_processes(thresholds: ThresholdConfig) -> CheckResult:
    if not command_exists("ps"):
        return CheckResult("running_processes", "info", "ps command not available", {"available": False, "count": 0, "processes": []})
    ok = False
    output = ""
    for cmd in (["ps", "-A", "-o", "pid,ppid,comm"], ["ps", "-ef"], ["ps"]):
        ok, output = run_command(cmd)
        if ok:
            break
    if not ok:
        return CheckResult("running_processes", "warning", "failed to collect running processes", {"available": True, "error": output, "count": 0, "processes": []})
    lines = [line for line in output.splitlines() if line.strip()]
    if lines and any(head in lines[0] for head in ("PID", "UID", "USER")):
        lines = lines[1:]
    status = "warning" if len(lines) > thresholds.process_warning_count else "ok"
    return CheckResult("running_processes", status, f"{len(lines)} processes observed", {"available": True, "count": len(lines), "processes": lines[:200]})


def check_sensitive_permissions() -> CheckResult:
    findings: list[str] = []
    for target in SENSITIVE_PATHS:
        if not target.exists():
            continue
        st = target.stat()
        mode = oct(st.st_mode & 0o777)
        if (st.st_mode & 0o077) != 0:
            findings.append(f"{target} permissions too broad: {mode}")
    status = "warning" if findings else "ok"
    summary = f"{len(findings)} permission issue(s)" if findings else "sensitive file permissions look strict"
    return CheckResult("sensitive_permissions", status, summary, {"findings": findings})


def check_package_hygiene(thresholds: ThresholdConfig) -> CheckResult:
    if not command_exists("pkg"):
        return CheckResult("package_hygiene", "info", "pkg command not available", {"available": False, "outdated_count": 0})
    ok, output = run_command(["pkg", "list-upgradable"])
    if not ok:
        return CheckResult("package_hygiene", "warning", "failed to list upgradable packages", {"available": True, "error": output, "outdated_count": 0})
    lines = [ln.strip() for ln in output.splitlines() if ln.strip() and not ln.lower().startswith("listing")]
    status = "warning" if len(lines) >= thresholds.package_outdated_warning_count else "ok"
    return CheckResult("package_hygiene", status, f"{len(lines)} upgradable package(s)", {"available": True, "outdated_count": len(lines), "packages": lines[:100]})


def check_local_persistence() -> CheckResult:
    candidates = [Path.home() / ".bashrc", Path.home() / ".zshrc", Path.home() / ".profile"]
    risky_patterns = ("nc ", "ncat ", "curl ", "wget ", "python -c", "termux-wake-lock")
    findings: list[str] = []
    for file in candidates:
        if not file.exists() or not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            low = line.lower().strip()
            if any(pat in low for pat in risky_patterns):
                findings.append(f"{file}:{idx}: {line[:120]}")
    status = "warning" if findings else "ok"
    return CheckResult("local_persistence", status, f"{len(findings)} suspicious startup line(s)", {"findings": findings})


def check_outbound_connections() -> CheckResult:
    if command_exists("ss"):
        ok, output = run_command(["ss", "-tun"])
    elif command_exists("netstat"):
        ok, output = run_command(["netstat", "-tun"])
    else:
        return CheckResult("outbound_connections", "info", "ss/netstat not available", {"available": False})
    if not ok:
        return CheckResult("outbound_connections", "warning", "failed to collect connections", {"available": True, "error": output})
    lines = [line for line in output.splitlines() if line.strip()]
    established = [ln for ln in lines if "ESTAB" in ln or "ESTABLISHED" in ln]
    return CheckResult("outbound_connections", "ok", f"{len(established)} established connection(s)", {"available": True, "connections": established[:200]})


def check_binary_integrity() -> CheckResult:
    binaries = ["python", "ssh", "ss", "termux-battery-status"]
    hashes: dict[str, str] = {}
    for name in binaries:
        path = shutil.which(name)
        if not path:
            continue
        try:
            with open(path, "rb") as fh:
                hashes[name] = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            continue
    return CheckResult("binary_integrity", "ok", f"hashed {len(hashes)} binaries", {"hashes": hashes})
