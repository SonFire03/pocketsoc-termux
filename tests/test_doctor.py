from pocketsoc.doctor import run_doctor


def test_doctor_shape() -> None:
    out = run_doctor()
    assert "checks" in out
    assert "missing" in out
