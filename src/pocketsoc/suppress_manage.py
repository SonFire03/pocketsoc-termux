from __future__ import annotations

from .suppress import load_suppressions, save_suppressions


def list_suppressions(data_dir=None) -> list[dict]:
    items = load_suppressions(data_dir)
    for i, item in enumerate(items, start=1):
        item.setdefault("id", i)
    return items


def remove_suppression(idx: int, data_dir=None) -> dict:
    items = load_suppressions(data_dir)
    if idx < 1 or idx > len(items):
        return {"removed": False, "error": "index out of range"}
    removed = items.pop(idx - 1)
    save_suppressions(items, data_dir)
    return {"removed": True, "item": removed}
