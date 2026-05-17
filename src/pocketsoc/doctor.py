from __future__ import annotations

from .system import command_exists


def run_doctor() -> dict:
    checks = {
        "ip": command_exists("ip"),
        "ss": command_exists("ss"),
        "pkg": command_exists("pkg"),
        "termux-battery-status": command_exists("termux-battery-status"),
        "termux-notification": command_exists("termux-notification"),
    }
    missing = [k for k, ok in checks.items() if not ok]
    return {"ok": len(missing) == 0, "checks": checks, "missing": missing}
