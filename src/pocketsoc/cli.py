from __future__ import annotations

from pathlib import Path

import typer
from rich import print
from rich.console import Console

from .alerts import calculate_risk_score
from .config import load_threshold_config, write_default_config
from .output.files import export_markdown_report, load_alerts, load_last_scan, load_scan_history, save_alerts, save_scan
from .output.render import render_alerts, render_dashboard_summary, render_scan, render_trends
from .redaction import redact_scan_data
from .scanner import run_scan


app = typer.Typer(help="PocketSOC: lightweight defensive monitoring for Termux.")
console = Console()


def _resolve_data_dir(data_dir: str | None) -> Path | None:
    if data_dir is None:
        return None
    return Path(data_dir).expanduser().resolve()


def _exit_on_alert_threshold(payload: dict, fail_on_alert: str) -> None:
    if fail_on_alert == "none":
        return
    ranking = {"low": 1, "medium": 2, "high": 3}
    threshold = ranking[fail_on_alert]
    for alert in payload.get("alerts", []):
        if ranking.get(alert.get("severity", "low"), 0) >= threshold:
            raise typer.Exit(code=2)


@app.command("init-config")
def init_config(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    force: bool = typer.Option(False, help="Overwrite existing config file."),
) -> None:
    root = _resolve_data_dir(data_dir)
    target = write_default_config(root, force=force)
    print(f"[green]Config ready:[/green] {target}")


@app.command()
def scan(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    quiet: bool = typer.Option(False, help="Minimal output mode."),
    output: str = typer.Option("table", help="Output format: table or json."),
    fail_on_alert: str = typer.Option("none", help="Fail if alerts >= severity: none|low|medium|high."),
    redact: bool = typer.Option(False, help="Redact sensitive values in displayed/saved report outputs."),
) -> None:
    root = _resolve_data_dir(data_dir)
    thresholds = load_threshold_config(root)
    result = run_scan(thresholds)
    save_scan(result, root)
    save_alerts(result, root)

    scan_payload = load_last_scan(root)
    alerts_payload = load_alerts(root)
    if redact:
        scan_payload, alerts_payload = redact_scan_data(scan_payload, alerts_payload)

    if not quiet:
        from pocketsoc.models import Alert, CheckResult, ScanResult

        checks = [CheckResult(**c) for c in scan_payload.get("checks", [])]
        alerts_data = [Alert(**a) for a in alerts_payload.get("alerts", [])]
        hydrated = ScanResult(scan_payload.get("timestamp", "n/a"), checks, alerts_data, alerts_payload.get("risk_score", calculate_risk_score(alerts_data)))
        if output == "json":
            console.print_json(data={"scan": scan_payload, "alerts": alerts_payload})
        else:
            render_scan(hydrated)
            render_alerts(hydrated)
            print(f"[green]Risk score:[/green] {hydrated.risk_score}")

    _exit_on_alert_threshold(alerts_payload, fail_on_alert)


@app.command()
def dashboard(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)

    if not scan_data:
        print("[yellow]No scan found. Run 'pocketsoc scan' first.[/yellow]")
        raise typer.Exit(code=1)

    from pocketsoc.models import Alert, CheckResult, ScanResult

    checks = [CheckResult(**c) for c in scan_data.get("checks", [])]
    alerts = [Alert(**a) for a in scan_data.get("alerts", [])]
    hydrated = ScanResult(scan_data.get("timestamp", "n/a"), checks, alerts, scan_data.get("risk_score", 0))
    render_dashboard_summary(hydrated)
    render_scan(hydrated)


@app.command()
def trends(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    root = _resolve_data_dir(data_dir)
    render_trends(load_scan_history(root))


@app.command()
def report(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    redact: bool = typer.Option(False, help="Redact sensitive values in report."),
) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)

    if not scan_data:
        print("[yellow]No scan found. Run 'pocketsoc scan' first.[/yellow]")
        raise typer.Exit(code=1)

    alerts = load_alerts(root)
    if redact:
        scan_data, alerts = redact_scan_data(scan_data, alerts)
    target = export_markdown_report(scan_data, alerts, root)
    print(f"[green]Report written:[/green] {target}")


@app.command()
def alerts(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    as_json: bool = typer.Option(True, "--json/--table", help="Display output as JSON or table."),
    redact: bool = typer.Option(False, help="Redact sensitive values in output."),
) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)
    payload = load_alerts(root)
    if redact:
        scan_data, payload = redact_scan_data(scan_data, payload)

    if as_json:
        console.print_json(data=payload)
        return

    from pocketsoc.models import Alert, CheckResult, ScanResult

    checks = [CheckResult(**c) for c in scan_data.get("checks", [])]
    alerts_data = [Alert(**a) for a in payload.get("alerts", [])]
    render_alerts(ScanResult(payload.get("timestamp", "n/a"), checks, alerts_data, payload.get("risk_score", 0)))


if __name__ == "__main__":
    app()
