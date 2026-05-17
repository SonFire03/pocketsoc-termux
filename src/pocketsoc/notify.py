from __future__ import annotations

from .system import command_exists, run_command


def notify_if_needed(risk_score: int, has_high: bool, threshold: int = 8) -> bool:
    if not command_exists("termux-notification"):
        return False
    if not has_high and risk_score < threshold:
        return False
    run_command([
        "termux-notification",
        "--title",
        "PocketSOC Alert",
        "--content",
        f"Risk score={risk_score}, high_alert={has_high}",
    ])
    return True
