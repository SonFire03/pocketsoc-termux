from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .output.files import ensure_data_dir


CONFIG_FILE = "config.json"


@dataclass(slots=True)
class ThresholdConfig:
    storage_warning_pct: float = 85.0
    storage_critical_pct: float = 95.0
    battery_warning_pct: float = 20.0
    battery_critical_pct: float = 10.0
    process_warning_count: int = 250
    listening_ports_warning_count: int = 25
    package_outdated_warning_count: int = 10


def preset_config(profile: str) -> ThresholdConfig:
    if profile == "strict":
        return ThresholdConfig(80.0, 90.0, 25.0, 15.0, 180, 15, 5)
    if profile == "battery-saver":
        return ThresholdConfig(90.0, 97.0, 30.0, 20.0, 300, 30, 15)
    return ThresholdConfig()


def _sanitize(raw: dict) -> ThresholdConfig:
    defaults = asdict(ThresholdConfig())
    merged = {**defaults, **(raw or {})}
    return ThresholdConfig(
        storage_warning_pct=float(merged["storage_warning_pct"]),
        storage_critical_pct=float(merged["storage_critical_pct"]),
        battery_warning_pct=float(merged["battery_warning_pct"]),
        battery_critical_pct=float(merged["battery_critical_pct"]),
        process_warning_count=int(merged["process_warning_count"]),
        listening_ports_warning_count=int(merged["listening_ports_warning_count"]),
        package_outdated_warning_count=int(merged["package_outdated_warning_count"]),
    )


def load_threshold_config(data_dir: Path | None = None) -> ThresholdConfig:
    root = ensure_data_dir(data_dir)
    target = root / CONFIG_FILE
    if not target.exists():
        return ThresholdConfig()

    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return ThresholdConfig()

    if not isinstance(payload, dict):
        return ThresholdConfig()

    return _sanitize(payload)


def write_default_config(data_dir: Path | None = None, force: bool = False, profile: str = "balanced") -> Path:
    root = ensure_data_dir(data_dir)
    target = root / CONFIG_FILE
    if target.exists() and not force:
        return target

    base = preset_config(profile)
    target.write_text(json.dumps(asdict(base), indent=2) + "\n", encoding="utf-8")
    return target
