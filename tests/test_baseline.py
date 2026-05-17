from pocketsoc.baseline import diff_baseline


def test_baseline_explain() -> None:
    current = {"alerts": [{"id": "A1"}], "checks": [{"name": "storage_usage", "status": "warning"}]}
    baseline = {"alerts": [], "checks": [{"name": "storage_usage", "status": "ok"}], "device_id": "dev1"}
    out = diff_baseline(current, baseline, explain=True)
    assert "explanation" in out
    assert out["device_id"] == "dev1"
