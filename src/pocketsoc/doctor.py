from __future__ import annotations

from .system import command_exists


def run_doctor(with_fix_hints: bool = False) -> dict:
    checks = {
        "ip": command_exists("ip"),
        "ss": command_exists("ss"),
        "pkg": command_exists("pkg"),
        "termux-battery-status": command_exists("termux-battery-status"),
        "termux-notification": command_exists("termux-notification"),
    }
    missing = [k for k, ok in checks.items() if not ok]
    out = {"ok": len(missing) == 0, "checks": checks, "missing": missing}
    if with_fix_hints:
        hints = []
        if "pkg" in missing:
            hints.append("Install Termux packages manager environment.")
        if "ss" in missing:
            hints.append("pkg install iproute2")
        if "termux-battery-status" in missing or "termux-notification" in missing:
            hints.append("pkg install termux-api && install Termux:API app")
        out["fix_hints"] = hints
    return out
