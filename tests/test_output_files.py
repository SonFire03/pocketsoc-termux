from pocketsoc.models import Alert, CheckResult, ScanResult
from pocketsoc.output.files import load_alerts, load_last_scan, prune_history, save_alerts, save_scan


def test_signed_save_load(tmp_path) -> None:
    scan = ScanResult(timestamp="2026-05-17T00:00:00+00:00", checks=[CheckResult(name="storage_usage", status="ok", summary="fine", details={})], alerts=[Alert(id="A", severity="low", title="t", description="d", source_check="storage_usage")], risk_score=1)
    save_scan(scan, tmp_path)
    save_alerts(scan, tmp_path)
    assert load_last_scan(tmp_path).get("schema_version") == "1.2"
    assert load_alerts(tmp_path).get("schema_version") == "1.2"


def test_prune_history(tmp_path) -> None:
    scan = ScanResult(timestamp="2026-05-17T00:00:00+00:00", checks=[], alerts=[], risk_score=0)
    save_scan(scan, tmp_path)
    save_scan(scan, tmp_path)
    kept = prune_history(tmp_path, max_scans=1)
    assert kept == 1
