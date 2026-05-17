from __future__ import annotations

import os


def is_readonly_mode() -> bool:
    return os.getenv("POCKETSOC_READONLY", "0") in {"1", "true", "TRUE", "yes", "YES"}
