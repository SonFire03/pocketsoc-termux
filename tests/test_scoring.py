from pocketsoc.models import CheckResult
from pocketsoc.scoring import category_scores


def test_category_scores() -> None:
    checks = [
        CheckResult(name="storage_usage", status="ok", summary="", details={}),
        CheckResult(name="running_processes", status="warning", summary="", details={}),
    ]
    out = category_scores(checks)
    assert "storage" in out
    assert "process" in out
