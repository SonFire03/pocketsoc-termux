import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app

runner = CliRunner()


def test_help_lists_new_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["serve", "ui-build", "policy-eval", "archive-rotate", "bundle", "doctor", "autofix-safe", "export"]:
        assert cmd in result.stdout
