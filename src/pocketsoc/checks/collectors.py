from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from ..config import ThresholdConfig
from ..models import CheckResult
from ..system import command_exists, parse_json, run_command

SENSITIVE_PATHS = [Path.home() / ".ssh", Path.home() / ".bashrc", Path.home() / ".zshrc", Path.home() / ".profile"]


def check_storage_usage(thresholds: ThresholdConfig, path: Path | None = None) -> CheckResult:
    target = path or Path.home()
    usage = shutil.disk_usage(target)
    used_pct = (usage.used / usage.total) * 100 if usage.total else 0
    status = "critical" if used_pct >= thresholds.storage_critical_pct else "warning" if used_pct >= thresholds.storage_warning_pct else "ok"
    return CheckResult("storage_usage", status, f"{used_pct:.1f}% used on {target}", {"path": str(target), "used_pct": round(used_pct, 2)})


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
    return CheckResult("battery_info", status, f"battery {pct}%", {"available": True, **payload})


def check_network_info() -> CheckResult:
    if command_exists("ip"):
        ok_addr, addr = run_command(["ip", "-brief", "address"])
        ok_route, route = run_command(["ip", "route"])
    elif command_exists("ifconfig"):
        ok_addr, addr = run_command(["ifconfig"])
        ok_route, route = run_command(["route", "-n"] if command_exists("route") else ["echo", ""])
    else:
        return CheckResult("network_info", "info", "ip/ifconfig command not available", {"available": False})
    return CheckResult("network_info", "ok" if ok_addr or ok_route else "warning", "network interfaces and routes collected", {"available": True, "address": addr if ok_addr else "", "routes": route if ok_route else ""})


def check_listening_ports(thresholds: ThresholdConfig) -> CheckResult:
    cmd = ["ss", "-tuln"] if command_exists("ss") else ["netstat", "-tuln"] if command_exists("netstat") else None
    if cmd is None:
        return CheckResult("listening_ports", "info", "ss/netstat not available", {"ports": []})
    ok, output = run_command(cmd)
    if not ok:
        return CheckResult("listening_ports", "warning", "failed to collect listening ports", {"error": output, "ports": []})
    lines = [x for x in output.splitlines() if x.strip()]
    if lines and ("Netid" in lines[0] or "Proto" in lines[0]):
        lines = lines[1:]
    return CheckResult("listening_ports", "warning" if len(lines) > thresholds.listening_ports_warning_count else "ok", f"{len(lines)} listening entries found", {"ports": lines})


def check_running_processes(thresholds: ThresholdConfig) -> CheckResult:
    if not command_exists("ps"):
        return CheckResult("running_processes", "info", "ps command not available", {"count": 0, "processes": []})
    ok, output = run_command(["ps", "-A", "-o", "pid,ppid,comm"])
    if not ok:
        ok, output = run_command(["ps", "-ef"])
    if not ok:
        return CheckResult("running_processes", "warning", "failed to collect running processes", {"count": 0, "processes": []})
    lines = [x for x in output.splitlines() if x.strip()]
    if lines and any(k in lines[0] for k in ("PID", "UID", "USER")):
        lines = lines[1:]
    return CheckResult("running_processes", "warning" if len(lines) > thresholds.process_warning_count else "ok", f"{len(lines)} processes observed", {"count": len(lines), "processes": lines[:200]})


def check_sensitive_permissions() -> CheckResult:
    findings = []
    for target in SENSITIVE_PATHS:
        if target.exists() and (target.stat().st_mode & 0o077) != 0:
            findings.append(f"{target} permissions too broad")
    return CheckResult("sensitive_permissions", "warning" if findings else "ok", f"{len(findings)} permission issue(s)", {"findings": findings})


def check_package_hygiene(thresholds: ThresholdConfig) -> CheckResult:
    if not command_exists("pkg"):
        return CheckResult("package_hygiene", "info", "pkg not available", {"outdated_count": 0})
    ok, output = run_command(["pkg", "list-upgradable"])
    if not ok:
        return CheckResult("package_hygiene", "warning", "failed to list upgradable packages", {"outdated_count": 0})
    pkgs = [x for x in output.splitlines() if x.strip() and not x.lower().startswith("listing")]
    return CheckResult("package_hygiene", "warning" if len(pkgs) >= thresholds.package_outdated_warning_count else "ok", f"{len(pkgs)} upgradable package(s)", {"outdated_count": len(pkgs), "packages": pkgs[:100]})


def check_local_persistence() -> CheckResult:
    files = [Path.home() / ".bashrc", Path.home() / ".zshrc", Path.home() / ".profile"]
    patterns = ("curl ", "wget ", "nc ", "python -c")
    findings = []
    for f in files:
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8", errors="ignore")
        for i, ln in enumerate(text.splitlines(), 1):
            if any(p in ln.lower() for p in patterns):
                findings.append(f"{f}:{i}:{ln[:120]}")
    return CheckResult("local_persistence", "warning" if findings else "ok", f"{len(findings)} suspicious startup line(s)", {"findings": findings})


def check_outbound_connections() -> CheckResult:
    cmd = ["ss", "-tun"] if command_exists("ss") else ["netstat", "-tun"] if command_exists("netstat") else None
    if cmd is None:
        return CheckResult("outbound_connections", "info", "ss/netstat not available", {})
    ok, output = run_command(cmd)
    if not ok:
        return CheckResult("outbound_connections", "warning", "failed to collect connections", {"connections": []})
    est = [ln for ln in output.splitlines() if "ESTAB" in ln or "ESTABLISHED" in ln]
    return CheckResult("outbound_connections", "ok", f"{len(est)} established connection(s)", {"connections": est[:200]})


def check_binary_integrity() -> CheckResult:
    hashes = {}
    for name in ["python", "ssh", "ss", "termux-battery-status"]:
        p = shutil.which(name)
        if not p:
            continue
        try:
            hashes[name] = hashlib.sha256(Path(p).read_bytes()).hexdigest()
        except OSError:
            continue
    return CheckResult("binary_integrity", "ok", f"hashed {len(hashes)} binaries", {"hashes": hashes})


def check_app_inventory() -> CheckResult:
    if not command_exists("pkg"):
        return CheckResult("app_inventory", "info", "pkg not available", {"packages": []})
    ok, output = run_command(["pkg", "list-installed"])
    if not ok:
        return CheckResult("app_inventory", "warning", "failed to list installed packages", {"packages": []})
    pkgs = [x.strip() for x in output.splitlines() if x.strip() and not x.lower().startswith("listing")]
    return CheckResult("app_inventory", "ok", f"{len(pkgs)} installed package(s)", {"packages": pkgs[:300]})
