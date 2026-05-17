from __future__ import annotations

from .safety import is_readonly_mode


def guard_mutation() -> None:
    if is_readonly_mode():
        raise PermissionError("POCKETSOC_READONLY=1 blocks mutating commands")
