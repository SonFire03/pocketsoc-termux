import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from pocketsoc.cli import app

runner = CliRunner()


def test_help_lists_new_commands() -> None:
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for cmd in ["watch", "suppress-add", "forensics-lite", "integrity-monitor", "bundle-verify"]:
        assert cmd in r.stdout


def test_mutating_help_has_dry_run() -> None:
    r = runner.invoke(app, ["history-prune", "--help"])
    assert "--dry-run" in r.stdout
