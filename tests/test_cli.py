import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app

runner = CliRunner()


def test_help_lists_new_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["deps-verify", "config-backup", "config-restore", "serve", "ui-build", "policy-eval", "archive-rotate", "bundle"]:
        assert cmd in result.stdout


def test_help_includes_new_options() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert "--parallel" in result.stdout
    assert "--since-last" in result.stdout


def test_policy_enforce_flag() -> None:
    result = runner.invoke(app, ["policy-eval", "--help"])
    assert "--enforce" in result.stdout
