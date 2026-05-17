from __future__ import annotations

from pathlib import Path

import typer
from rich import print

from .output.files import export_markdown_report, load_alerts, load_last_scan, save_alerts, save_scan
from .output.render import render_alerts, render_scan
from .scanner import run_scan


app = typer.Typer(help="PocketSOC: lightweight defensive monitoring for Termux.")


def _resolve_data_dir(data_dir: str | None) -> Path | None:
    if data_dir is None:
        return None
    return Path(data_dir).expanduser().resolve()


@app.command()
def scan(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    """Run local checks and persist JSON results."""
    root = _resolve_data_dir(data_dir)
    result = run_scan()
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
    render_scan(ScanResult(timestamp=scan_data.get("timestamp", "n/a"), checks=checks, alerts=alerts))


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
def alerts(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    """Display alerts from latest saved scan in JSON form."""
    root = _resolve_data_dir(data_dir)
    payload = load_alerts(root)
    print(payload)


if __name__ == "__main__":
    app()
