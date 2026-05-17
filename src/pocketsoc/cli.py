from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import typer
from rich import print
from rich.console import Console

from .alerts import calculate_risk_score
from .autofix import run_autofix_safe
from .baseline import create_baseline, diff_baseline, load_baseline
from .config import load_threshold_config, write_default_config
from .doctor import run_doctor
from .exporters import export_siem
from .notify import notify_if_needed
from .output.files import (
    export_markdown_report,
    export_trends_csv,
    load_alerts,
    load_last_scan,
    load_scan_history,
    prune_history,
    save_alerts,
    save_scan,
)
from .output.render import render_alerts, render_dashboard_summary, render_scan, render_trends
from .redaction import redact_scan_data
from .rules import write_default_rules
from .scanner import run_scan
from .scheduler import install_schedule

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


@app.command("doctor", help="Check local dependencies and Termux command availability.")
def doctor() -> None:
    console.print_json(data=run_doctor())


@app.command("autofix-safe", help="Apply non-destructive local fixes (config/rules bootstrap).")
def autofix_safe(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    console.print_json(data=run_autofix_safe(_resolve_data_dir(data_dir)))


@app.command("init-config", help="Create or overwrite threshold configuration presets.")
def init_config(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    force: bool = typer.Option(False, help="Overwrite existing config file."),
    profile: Literal["balanced", "strict", "battery-saver"] = typer.Option("balanced", help="Threshold preset profile."),
) -> None:
    print(f"[green]Config ready:[/green] {write_default_config(_resolve_data_dir(data_dir), force=force, profile=profile)}")


@app.command("init-rules", help="Create or overwrite custom rule definitions.")
def init_rules(data_dir: str | None = typer.Option(None, help="Override data directory."), force: bool = typer.Option(False, help="Overwrite existing rules file.")) -> None:
    print(f"[green]Rules ready:[/green] {write_default_rules(_resolve_data_dir(data_dir), force=force)}")


@app.command(help="Run a defensive local scan and persist signed artifacts.")
def scan(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    profile: Literal["quick", "standard", "deep"] = typer.Option("standard", help="Scan profile."),
    time_profile: Literal["auto", "day", "night"] = typer.Option("auto", help="Temporal profile for threshold tuning."),
    quiet: bool = typer.Option(False, help="Minimal output mode."),
    output: Literal["table", "json", "ndjson"] = typer.Option("table", help="Output format."),
    fail_on_alert: Literal["none", "low", "medium", "high"] = typer.Option("none", help="Exit with code 2 if alerts reach this severity."),
    redact: bool = typer.Option(False, help="Redact sensitive values in output."),
    notify: bool = typer.Option(True, help="Send local Termux notification on critical risk."),
) -> None:
    root = _resolve_data_dir(data_dir)
    thresholds = load_threshold_config(root)
    result = run_scan(thresholds, profile=profile, rules_data_dir=root)
    if time_profile in ("auto", "night"):
        result.risk_score += 1
    save_scan(result, root)
    save_alerts(result, root)

    scan_payload = load_last_scan(root)
    alerts_payload = load_alerts(root)
    if redact:
        scan_payload, alerts_payload = redact_scan_data(scan_payload, alerts_payload)

    if notify:
        high = any(a.get("severity") == "high" for a in alerts_payload.get("alerts", []))
        notify_if_needed(alerts_payload.get("risk_score", 0), high)

    if not quiet:
        if output == "json":
            console.print_json(data={"scan": scan_payload, "alerts": alerts_payload})
        elif output == "ndjson":
            typer.echo(json.dumps(scan_payload))
            typer.echo(json.dumps(alerts_payload))
        else:
            from pocketsoc.models import Alert, CheckResult, ScanResult

            checks = [CheckResult(**c) for c in scan_payload.get("checks", [])]
            alerts_data = [Alert(**a) for a in alerts_payload.get("alerts", [])]
            hydrated = ScanResult(scan_payload.get("timestamp", "n/a"), checks, alerts_data, alerts_payload.get("risk_score", calculate_risk_score(alerts_data)))
            render_scan(hydrated)
            render_alerts(hydrated)
            print(f"[green]Risk score:[/green] {hydrated.risk_score}")

    _exit_on_alert_threshold(alerts_payload, fail_on_alert)


@app.command(help="Show current scan status summary and per-check table.")
def dashboard(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)
    if not scan_data or scan_data.get("integrity_error"):
        raise typer.Exit(code=1)
    from pocketsoc.models import Alert, CheckResult, ScanResult

    checks = [CheckResult(**c) for c in scan_data.get("checks", [])]
    alerts = [Alert(**a) for a in scan_data.get("alerts", [])]
    hydrated = ScanResult(scan_data.get("timestamp", "n/a"), checks, alerts, scan_data.get("risk_score", 0))
    render_dashboard_summary(hydrated)
    render_scan(hydrated)


@app.command(help="Display recent scan trends and optionally export CSV.")
def trends(data_dir: str | None = typer.Option(None, help="Override data directory."), csv: bool = typer.Option(False, "--csv", help="Export trends to CSV.")) -> None:
    root = _resolve_data_dir(data_dir)
    history = load_scan_history(root)
    render_trends(history)
    if csv:
        print(f"[green]CSV exported:[/green] {export_trends_csv(history, root)}")


@app.command("baseline-create", help="Create a baseline snapshot from the latest scan.")
def baseline_create(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    profile: Literal["quick", "standard", "deep"] = typer.Option("standard", help="Associated profile label."),
    device_id: str = typer.Option("local-device", help="Logical device identifier for multi-host baselines."),
) -> None:
    root = _resolve_data_dir(data_dir)
    if not load_last_scan(root):
        raise typer.Exit(code=1)
    print(f"[green]Baseline saved:[/green] {create_baseline(root, profile, device_id=device_id)}")


@app.command("baseline-diff", help="Compare latest scan against stored baseline.")
def baseline_diff(
    data_dir: str | None = typer.Option(None, help="Override data directory."),
    tolerance: int = typer.Option(0, help="Ignore <= tolerance new alerts."),
    explain: bool = typer.Option(False, help="Include explanation text in diff output."),
) -> None:
    root = _resolve_data_dir(data_dir)
    current = load_last_scan(root)
    baseline = load_baseline(root)
    if not current or not baseline:
        raise typer.Exit(code=1)
    console.print_json(data=diff_baseline(current, baseline, tolerance=tolerance, explain=explain))


@app.command("history-prune", help="Prune scan history by age and/or maximum number of scans.")
def history_prune(data_dir: str | None = typer.Option(None, help="Override data directory."), days: int | None = typer.Option(None, help="Keep only scans from the last N days."), max_scans: int | None = typer.Option(None, help="Keep only the last N scans.")) -> None:
    print(f"[green]History pruned. Entries kept:[/green] {prune_history(_resolve_data_dir(data_dir), days=days, max_scans=max_scans)}")


@app.command("schedule-install", help="Install a local scheduled scan script and schedule metadata.")
def schedule_install(data_dir: str | None = typer.Option(None, help="Override data directory."), interval: str = typer.Option("6h", help="Human interval metadata (e.g. 6h, 12h, 1d).")) -> None:
    print(f"[green]Schedule installed:[/green] {install_schedule(interval, _resolve_data_dir(data_dir))}")


@app.command("verify-integrity", help="Verify signatures for last scan and alerts payloads.")
def verify_integrity(data_dir: str | None = typer.Option(None, help="Override data directory.")) -> None:
    root = _resolve_data_dir(data_dir)
    s = load_last_scan(root)
    a = load_alerts(root)
    if not s.get("integrity_error") and not a.get("integrity_error"):
        print("[green]Integrity verification passed.[/green]")
    else:
        raise typer.Exit(code=2)


@app.command("export", help="Export alerts for SIEM ingestion formats.")
def export_cmd(data_dir: str | None = typer.Option(None, help="Override data directory."), fmt: Literal["cef", "syslog-json"] = typer.Option("syslog-json", help="Target export format.")) -> None:
    print(f"[green]Export written:[/green] {export_siem(_resolve_data_dir(data_dir), fmt)}")


@app.command(help="Export a Markdown report from latest signed data.")
def report(data_dir: str | None = typer.Option(None, help="Override data directory."), redact: bool = typer.Option(False, help="Redact sensitive values in report.")) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)
    alerts = load_alerts(root)
    if not scan_data or scan_data.get("integrity_error"):
        raise typer.Exit(code=1)
    if redact:
        scan_data, alerts = redact_scan_data(scan_data, alerts)
    print(f"[green]Report written:[/green] {export_markdown_report(scan_data, alerts, root)}")


@app.command(help="Display alerts as JSON or formatted table.")
def alerts(data_dir: str | None = typer.Option(None, help="Override data directory."), as_json: bool = typer.Option(True, "--json/--table", help="Display output as JSON or table."), redact: bool = typer.Option(False, help="Redact sensitive values in output.")) -> None:
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


@app.command("release-tag", help="Print recommended semantic version tag and release note template.")
def release_tag(version: str = typer.Option("v0.6.0", help="Target semver tag.")) -> None:
    typer.echo(f"Tag: {version}\\nRelease notes: scan hardening + automation + integration outputs.")


if __name__ == "__main__":
    app()
