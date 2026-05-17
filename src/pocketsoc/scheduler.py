from __future__ import annotations

from pathlib import Path

from .output.files import ensure_data_dir


def install_schedule(interval: str, data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    script = root / "scheduled-scan.sh"
    script.write_text(
        "#!/data/data/com.termux/files/usr/bin/sh\n"
        "set -eu\n"
        "LOCK=\"$HOME/.pocketsoc/.scan.lock\"\n"
        "if [ -f \"$LOCK\" ]; then exit 0; fi\n"
        "trap 'rm -f \"$LOCK\"' EXIT\n"
        "touch \"$LOCK\"\n"
        "pocketsoc scan --quiet --profile standard\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    conf = root / "schedule.txt"
    conf.write_text(f"interval={interval}\nscript={script}\n", encoding="utf-8")
    return conf
