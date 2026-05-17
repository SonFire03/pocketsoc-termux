from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class CheckResult:
    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Alert:
    id: str
    severity: str
    title: str
    description: str
    source_check: str


@dataclass(slots=True)
class ScanResult:
    timestamp: str
    checks: list[CheckResult]
    alerts: list[Alert]


DEFAULT_DATA_DIR_NAME = ".pocketsoc"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
