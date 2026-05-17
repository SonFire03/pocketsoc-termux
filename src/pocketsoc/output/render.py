from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..models import ScanResult


console = Console()


def render_scan(scan: ScanResult) -> None:
    table = Table(title=f"PocketSOC Scan ({scan.timestamp})")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Summary")

    for check in scan.checks:
        style = {
            "ok": "green",
            "warning": "yellow",
            "critical": "red",
            "info": "blue",
        }.get(check.status, "white")
        table.add_row(check.name, f"[{style}]{check.status}[/{style}]", check.summary)

    console.print(table)


def render_alerts(scan: ScanResult) -> None:
    if not scan.alerts:
        console.print("[green]No alerts generated.[/green]")
        return

    table = Table(title="PocketSOC Alerts")
    table.add_column("ID", style="magenta")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Check", style="cyan")

    for alert in scan.alerts:
        sev_style = {"high": "red", "medium": "yellow", "low": "blue"}.get(alert.severity, "white")
        table.add_row(
            alert.id,
            f"[{sev_style}]{alert.severity}[/{sev_style}]",
            alert.title,
            alert.source_check,
        )

    console.print(table)
