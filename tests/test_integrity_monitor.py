from pocketsoc.integrity_monitor import run_integrity_monitor


def test_integrity_monitor_shape(tmp_path) -> None:
    out = run_integrity_monitor(tmp_path)
    assert "ok" in out
    assert "issues" in out
