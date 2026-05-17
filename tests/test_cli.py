import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app

runner = CliRunner()


def test_help_lists_new_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "history-prune" in result.stdout
    assert "schedule-install" in result.stdout
    assert "verify-integrity" in result.stdout


def test_init_files(tmp_path) -> None:
    assert runner.invoke(app, ["init-config", "--data-dir", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["init-rules", "--data-dir", str(tmp_path)]).exit_code == 0
