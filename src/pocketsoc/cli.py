from __future__ import annotations

from pathlib import Path

import typer
from rich import print
from rich.console import Console

from .config import load_threshold_config, write_default_config
from .output.files import export_markdown_report, load_alerts, load_last_scan, save_alerts, save_scan
from .output.render import render_alerts, render_dashboard_summary, render_scan
from .scanner import run_scan


app = typer.Typer(help="PocketSOC: lightweight defensive monitoring for Termux.")
console = Console()


def _resolve_data_dir(data_dir: str | None) -> Path | None:
    if data_dir is None:
        return None
    return Path(data_dir).expanduser().resolve()


@app.command()
def init_config(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    force: bool = typer.Option(False, help="Overwrite existing config file."),
) -> None:
    """Create default JSON config for thresholds."""
    root = _resolve_data_dir(data_dir)
    target = write_default_config(root, force=force)
    print(f"[green]Config ready:[/green] {target}")


@app.command()
def scan(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    """Run local checks and persist JSON results."""
    root = _resolve_data_dir(data_dir)
    thresholds = load_threshold_config(root)
    result = run_scan(thresholds)
    scan_path = save_scan(result, root)
    alerts_path = save_alerts(result, root)
    render_scan(result)
    render_alerts(result)
    print(f"[green]Saved scan:[/green] {scan_path}")
    print(f"[green]Saved alerts:[/green] {alerts_path}")


@app.command()
def dashboard(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    """Display latest scan snapshot."""
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)

    if not scan_data:
        print("[yellow]No scan found. Run 'pocketsoc scan' first.[/yellow]")
        raise typer.Exit(code=1)

    from pocketsoc.models import Alert, CheckResult, ScanResult

    checks = [CheckResult(**c) for c in scan_data.get("checks", [])]
    alerts = [Alert(**a) for a in scan_data.get("alerts", [])]
    hydrated = ScanResult(timestamp=scan_data.get("timestamp", "n/a"), checks=checks, alerts=alerts)
    render_dashboard_summary(hydrated)
    render_scan(hydrated)


@app.command()
def report(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    """Export markdown report from latest JSON data."""
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)

    if not scan_data:
        print("[yellow]No scan found. Run 'pocketsoc scan' first.[/yellow]")
        raise typer.Exit(code=1)

    alerts = load_alerts(root)
    target = export_markdown_report(scan_data, alerts, root)
    print(f"[green]Report written:[/green] {target}")


@app.command()
def alerts(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    as_json: bool = typer.Option(True, "--json/--table", help="Display output as JSON or table."),
) -> None:
    """Display latest alerts."""
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)
    payload = load_alerts(root)

    if as_json:
        console.print_json(data=payload)
        return

    from pocketsoc.models import Alert, CheckResult, ScanResult

    checks = [CheckResult(**c) for c in scan_data.get("checks", [])]
    alerts_data = [Alert(**a) for a in payload.get("alerts", [])]
    render_alerts(ScanResult(timestamp=payload.get("timestamp", "n/a"), checks=checks, alerts=alerts_data))


if __name__ == "__main__":
    app()
