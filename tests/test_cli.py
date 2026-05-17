import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app

runner = CliRunner()


def test_help_lists_new_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["api-key-rotate", "bundle-verify", "explain-alert", "deps-verify", "config-backup", "config-restore"]:
        assert cmd in result.stdout


def test_scan_help_new_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert "--timeout" in result.stdout
    assert "--resource-profile" in result.stdout
    assert "--parallel" in result.stdout
