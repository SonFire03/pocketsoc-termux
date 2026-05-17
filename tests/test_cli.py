import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app


runner = CliRunner()


def test_scan_command_runs(monkeypatch, tmp_path) -> None:
    from pocketsoc.models import ScanResult

    def fake_run_scan(_thresholds) -> ScanResult:
        from pocketsoc.models import CheckResult

        return ScanResult(
            timestamp="2026-05-17T00:00:00+00:00",
            checks=[CheckResult(name="storage_usage", status="ok", summary="fine", details={})],
            alerts=[],
        )

    monkeypatch.setattr("pocketsoc.cli.run_scan", fake_run_scan)

    result = runner.invoke(app, ["scan", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0


def test_dashboard_requires_scan(tmp_path) -> None:
    result = runner.invoke(app, ["dashboard", "--data-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "No scan found" in result.stdout


def test_init_config_creates_file(tmp_path) -> None:
    result = runner.invoke(app, ["init-config", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "config.json").exists()
