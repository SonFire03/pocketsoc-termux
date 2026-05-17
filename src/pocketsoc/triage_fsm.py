from __future__ import annotations

ALLOWED = {
    "new": {"investigating", "false_positive"},
    "investigating": {"mitigated", "false_positive"},
    "mitigated": set(),
    "false_positive": set(),
}


def validate_transition(old: str, new: str, comment: str) -> tuple[bool, str]:
    if old == new:
        return True, ""
    allowed = ALLOWED.get(old, set())
    if new in allowed:
        return True, ""
    if new == "new" and old in {"mitigated", "false_positive"} and comment.strip():
        return True, "reopened with justification"
    return False, f"invalid transition {old} -> {new}"
