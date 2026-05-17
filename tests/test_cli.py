import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app

runner = CliRunner()


def test_help_has_new_commands() -> None:
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for cmd in ["scan", "report", "baseline", "api", "maint", "config"]:
        assert cmd in r.stdout


def test_report_help_has_diff_and_timeline() -> None:
    r = runner.invoke(app, ["report", "--help"])
    assert "diff" in r.stdout
    assert "timeline" in r.stdout


def test_config_help_has_suppress_manage() -> None:
    r = runner.invoke(app, ["config", "--help"])
    assert "suppress-list" in r.stdout
    assert "suppress-remove" in r.stdout
