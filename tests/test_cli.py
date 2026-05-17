import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app

runner = CliRunner()


def test_top_level_help_works() -> None:
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0


def test_scan_help_works() -> None:
    r = runner.invoke(app, ["scan", "--help"])
    assert r.exit_code == 0


def test_report_help_works() -> None:
    r = runner.invoke(app, ["report", "--help"])
    assert r.exit_code == 0


def test_config_help_works() -> None:
    r = runner.invoke(app, ["config", "--help"])
    assert r.exit_code == 0


def test_quick_demo_commands_are_available() -> None:
    assert runner.invoke(app, ["config", "init", "--help"]).exit_code == 0
    assert runner.invoke(app, ["scan", "run", "--help"]).exit_code == 0
    assert runner.invoke(app, ["scan", "dashboard", "--help"]).exit_code == 0
    assert runner.invoke(app, ["scan", "alerts", "--help"]).exit_code == 0
    assert runner.invoke(app, ["report", "md", "--help"]).exit_code == 0
