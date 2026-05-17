from pathlib import Path

from pocketsoc.deps import verify_lock


def test_verify_lock() -> None:
    p = Path('/tmp/pocketsoc-lock.txt')
    p.write_text('typer==0.12.3\n', encoding='utf-8')
    out = verify_lock(p)
    assert out['ok'] is True
