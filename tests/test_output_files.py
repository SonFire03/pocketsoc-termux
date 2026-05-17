from pocketsoc.models import Alert, CheckResult, ScanResult
from pocketsoc.output.files import export_markdown_report, load_alerts, load_last_scan, save_alerts, save_scan


def test_save_and_load_scan_and_alerts(tmp_path) -> None:
    scan = ScanResult(
        timestamp="2026-05-17T00:00:00+00:00",
        checks=[CheckResult(name="storage_usage", status="ok", summary="fine", details={})],
        alerts=[
            Alert(
                id="ALERT-1",
                severity="low",
                title="Test",
                description="test",
                source_check="storage_usage",
            )
        ],
    )

    save_scan(scan, tmp_path)
    save_alerts(scan, tmp_path)

    loaded_scan = load_last_scan(tmp_path)
    loaded_alerts = load_alerts(tmp_path)

    assert loaded_scan["timestamp"] == scan.timestamp
    assert len(loaded_alerts["alerts"]) == 1


def test_export_markdown_report(tmp_path) -> None:
    scan = {
        "timestamp": "2026-05-17T00:00:00+00:00",
        "checks": [{"name": "storage_usage", "status": "ok", "summary": "fine"}],
    }
    alerts = {"alerts": []}
    target = export_markdown_report(scan, alerts, tmp_path)
    content = target.read_text(encoding="utf-8")
    assert "# PocketSOC Report" in content
    assert "No alerts." in content
