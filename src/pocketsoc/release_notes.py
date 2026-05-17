from __future__ import annotations

from pathlib import Path


def generate_release_notes(changelog_path: Path) -> str:
    text = changelog_path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    title = lines[1] if len(lines) > 1 else "Release"
    bullets = [ln for ln in lines if ln.startswith("- ")][:10]
    return title + "\n\n" + "\n".join(bullets)
