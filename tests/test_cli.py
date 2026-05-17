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
