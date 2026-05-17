from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Literal

import typer
from rich import print
from rich.console import Console

from .alerts import calculate_risk_score
from .api_server import serve_api
from .api_token import rotate_api_token
from .archive import rotate_history_archive
from .audit_export import export_audit
from .autofix import run_autofix_safe
from .baseline import create_baseline, diff_baseline, load_baseline
from .bundle import build_incident_bundle
from .bundle_sign import sign_bundle, verify_bundle
from .config import load_threshold_config, write_default_config
from .configio import backup_config, restore_config
from .deps import verify_lock
from .doctor import run_doctor
from .explain import explain_alert
from .exporters import export_siem
from .forensics import build_forensics_snapshot
from .forensics_verify import verify_forensics_snapshot
from .integrity_monitor import run_integrity_monitor
from .notify import notify_if_needed
from .output.files import export_markdown_report, export_trends_csv, load_alerts, load_last_scan, load_scan_history, prune_history, save_alerts, save_scan
from .output.render import render_alerts, render_dashboard_summary, render_scan, render_trends
from .policy import eval_policy, write_default_policy
from .readonly import guard_mutation
from .redaction import redact_scan_data
from .report_diff import diff_scans, load_scan_file
from .rules import write_default_rules
from .scanner import run_scan, scan_plan
from .scheduler import install_schedule
from .suppress import add_suppression
from .suppress_manage import list_suppressions, remove_suppression
from .webui import write_web_ui

app = typer.Typer(help="PocketSOC CLI")
scan_app = typer.Typer(help="Scan and monitoring commands")
report_app = typer.Typer(help="Reporting and export commands")
baseline_app = typer.Typer(help="Baseline and policy commands")
api_app = typer.Typer(help="API and web commands")
maint_app = typer.Typer(help="Maintenance and integrity commands")
config_app = typer.Typer(help="Configuration and setup commands")

app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(baseline_app, name="baseline")
app.add_typer(api_app, name="api")
app.add_typer(maint_app, name="maint")
app.add_typer(config_app, name="config")

console = Console()


def _resolve_data_dir(data_dir: str | None) -> Path | None:
    return Path(data_dir).expanduser().resolve() if data_dir else None


def _exit_on_alert_threshold(payload: dict, fail_on_alert: str) -> None:
    if fail_on_alert == "none":
        return
    ranking = {"low": 1, "medium": 2, "high": 3}
    for alert in payload.get("alerts", []):
        if ranking.get(alert.get("severity", "low"), 0) >= ranking[fail_on_alert]:
            raise typer.Exit(code=2)


@scan_app.command("plan", help="Show which checks would run for a given profile/resource profile.")
def scan_plan_cmd(profile: Literal["quick", "standard", "deep"] = typer.Option("standard"), resource_profile: Literal["low", "balanced", "high"] = typer.Option("balanced")) -> None:
    console.print_json(data=scan_plan(profile, resource_profile))


@scan_app.command("run", help="Run a defensive local scan and persist signed artifacts.")
def scan_run(data_dir: str | None = typer.Option(None), profile: Literal["quick", "standard", "deep"] = typer.Option("standard"), resource_profile: Literal["low", "balanced", "high"] = typer.Option("balanced"), time_profile: Literal["auto", "day", "night"] = typer.Option("auto"), since_last: bool = typer.Option(False), parallel: bool = typer.Option(False), timeout: int = typer.Option(60), quiet: bool = typer.Option(False), output: Literal["table", "json", "ndjson"] = typer.Option("table"), fail_on_alert: Literal["none", "low", "medium", "high"] = typer.Option("none"), redact: bool = typer.Option(False), notify: bool = typer.Option(True)) -> None:
    root = _resolve_data_dir(data_dir)
    thresholds = load_threshold_config(root)
    hist = load_scan_history(root)
    result = run_scan(thresholds, profile=profile, rules_data_dir=root, history=hist, since_last=since_last, parallel=parallel, timeout_seconds=timeout, resource_profile=resource_profile)
    if time_profile in ("auto", "night"):
        result.risk_score += 1
    save_scan(result, root)
    save_alerts(result, root)
    scan_payload, alerts_payload = load_last_scan(root), load_alerts(root)
    if redact:
        scan_payload, alerts_payload = redact_scan_data(scan_payload, alerts_payload)
    if notify:
        notify_if_needed(alerts_payload.get("risk_score", 0), any(a.get("severity") == "high" for a in alerts_payload.get("alerts", [])))
    if not quiet:
        if output == "json":
            console.print_json(data={"scan": scan_payload, "alerts": alerts_payload})
        elif output == "ndjson":
            typer.echo(json.dumps(scan_payload))
            typer.echo(json.dumps(alerts_payload))
        else:
            from pocketsoc.models import Alert, CheckResult, ScanResult
            hydrated = ScanResult(scan_payload.get("timestamp", "n/a"), [CheckResult(**c) for c in scan_payload.get("checks", [])], [Alert(**a) for a in alerts_payload.get("alerts", [])], alerts_payload.get("risk_score", calculate_risk_score([])))
            render_scan(hydrated)
            render_alerts(hydrated)
            if "category_scores" in scan_payload:
                console.print_json(data={"category_scores": scan_payload["category_scores"]})
            print(f"[green]Risk score:[/green] {hydrated.risk_score}")
    _exit_on_alert_threshold(alerts_payload, fail_on_alert)


@scan_app.command("watch", help="Continuously run scans at interval with incremental output.")
def scan_watch(data_dir: str | None = typer.Option(None), interval: int = typer.Option(60), profile: Literal["quick", "standard", "deep"] = typer.Option("standard")) -> None:
    while True:
        scan_run(data_dir=data_dir, profile=profile, quiet=False, output="table")
        time.sleep(max(5, interval))


@scan_app.command("dashboard", help="Show current scan status summary and per-check table.")
def scan_dashboard(data_dir: str | None = typer.Option(None)) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)
    from pocketsoc.models import Alert, CheckResult, ScanResult
    hydrated = ScanResult(scan_data.get("timestamp", "n/a"), [CheckResult(**c) for c in scan_data.get("checks", [])], [Alert(**a) for a in scan_data.get("alerts", [])], scan_data.get("risk_score", 0))
    render_dashboard_summary(hydrated)
    render_scan(hydrated)


@scan_app.command("alerts", help="Display alerts as JSON or formatted table.")
def scan_alerts(data_dir: str | None = typer.Option(None), as_json: bool = typer.Option(True, "--json/--table"), redact: bool = typer.Option(False)) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data, payload = load_last_scan(root), load_alerts(root)
    if redact:
        scan_data, payload = redact_scan_data(scan_data, payload)
    if as_json:
        console.print_json(data=payload)
        return
    from pocketsoc.models import Alert, CheckResult, ScanResult
    render_alerts(ScanResult(payload.get("timestamp", "n/a"), [CheckResult(**c) for c in scan_data.get("checks", [])], [Alert(**a) for a in payload.get("alerts", [])], payload.get("risk_score", 0)))


@scan_app.command("explain-alert", help="Explain why a specific alert ID was generated.")
def scan_explain_alert(alert_id: str, data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=explain_alert(alert_id, _resolve_data_dir(data_dir)))


@report_app.command("md", help="Export a Markdown report.")
def report_md(data_dir: str | None = typer.Option(None), redact: bool = typer.Option(False), report_format: Literal["full", "executive"] = typer.Option("full", "--format"), compare_baseline: bool = typer.Option(False, "--compare-baseline")) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data, alerts = load_last_scan(root), load_alerts(root)
    if redact:
        scan_data, alerts = redact_scan_data(scan_data, alerts)
    baseline_diff_data = diff_baseline(scan_data, load_baseline(root)) if compare_baseline else None
    print(f"[green]Report written:[/green] {export_markdown_report(scan_data, alerts, root, report_format=report_format, compare_baseline=baseline_diff_data)}")


@report_app.command("diff", help="Compare two scan JSON files directly.")
def report_diff(scan_a: str, scan_b: str) -> None:
    console.print_json(data=diff_scans(load_scan_file(Path(scan_a)), load_scan_file(Path(scan_b))))


@report_app.command("trends", help="Display trends and optionally export CSV.")
def report_trends(data_dir: str | None = typer.Option(None), csv: bool = typer.Option(False, "--csv")) -> None:
    root = _resolve_data_dir(data_dir)
    hist = load_scan_history(root)
    render_trends(hist)
    if csv:
        print(f"[green]CSV exported:[/green] {export_trends_csv(hist, root)}")


@report_app.command("export", help="Export alerts to SIEM-friendly format.")
def report_export(data_dir: str | None = typer.Option(None), fmt: Literal["cef", "syslog-json"] = typer.Option("syslog-json")) -> None:
    print(f"[green]Export written:[/green] {export_siem(_resolve_data_dir(data_dir), fmt)}")


@report_app.command("audit-export", help="Export API audit log in JSON or CSV.")
def report_audit_export(data_dir: str | None = typer.Option(None), fmt: Literal["json", "csv"] = typer.Option("json")) -> None:
    print(f"[green]Audit export written:[/green] {export_audit(_resolve_data_dir(data_dir), fmt=fmt)}")


@report_app.command("bundle", help="Build incident bundle ZIP from local artifacts.")
def report_bundle(data_dir: str | None = typer.Option(None), since: str = typer.Option("24h"), redact: bool = typer.Option(False, "--redact"), sign: bool = typer.Option(True, "--sign/--no-sign")) -> None:
    guard_mutation()
    root = _resolve_data_dir(data_dir)
    _ = since
    out = build_incident_bundle(root, redact=redact)
    if sign:
        sig = sign_bundle(out, root)
        print(f"[green]Bundle created:[/green] {out}\n[green]Signature:[/green] {sig}")
    else:
        print(f"[green]Bundle created:[/green] {out}")


@report_app.command("bundle-verify", help="Verify signature of a generated incident bundle.")
def report_bundle_verify(bundle_path: str, data_dir: str | None = typer.Option(None)) -> None:
    if not verify_bundle(Path(bundle_path), _resolve_data_dir(data_dir)):
        raise typer.Exit(code=2)
    print("[green]Bundle signature valid.[/green]")


@baseline_app.command("create", help="Create a baseline snapshot from latest scan.")
def baseline_create_cmd(data_dir: str | None = typer.Option(None), profile: Literal["quick", "standard", "deep"] = typer.Option("standard"), device_id: str = typer.Option("local-device")) -> None:
    guard_mutation()
    print(f"[green]Baseline saved:[/green] {create_baseline(_resolve_data_dir(data_dir), profile, device_id=device_id)}")


@baseline_app.command("diff", help="Compare latest scan against stored baseline.")
def baseline_diff_cmd(data_dir: str | None = typer.Option(None), tolerance: int = typer.Option(0), explain: bool = typer.Option(False)) -> None:
    root = _resolve_data_dir(data_dir)
    console.print_json(data=diff_baseline(load_last_scan(root), load_baseline(root), tolerance=tolerance, explain=explain))


@baseline_app.command("policy-eval", help="Evaluate latest scan against local compliance policy.")
def baseline_policy_eval(data_dir: str | None = typer.Option(None), enforce: bool = typer.Option(False, "--enforce"), baseline_aware: bool = typer.Option(False, "--baseline-aware")) -> None:
    res = eval_policy(_resolve_data_dir(data_dir), baseline_aware=baseline_aware)
    console.print_json(data=res)
    if enforce and not res.get("compliant", False):
        raise typer.Exit(code=2)


@api_app.command("serve", help="Start local read-only API server for scans/alerts/trends.")
def api_serve(host: str = typer.Option("127.0.0.1"), port: int = typer.Option(8787), data_dir: str | None = typer.Option(None)) -> None:
    serve_api(host, port, _resolve_data_dir(data_dir))


@api_app.command("key-rotate", help="Rotate local API read-only token file.")
def api_key_rotate_cmd(data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    print(f"[green]API token rotated:[/green] {rotate_api_token(_resolve_data_dir(data_dir))}")


@api_app.command("ui-build", help="Generate dynamic local web dashboard file.")
def api_ui_build(data_dir: str | None = typer.Option(None)) -> None:
    print(f"[green]UI generated:[/green] {write_web_ui(_resolve_data_dir(data_dir))}")


@maint_app.command("doctor", help="Check local dependencies and Termux command availability.")
def maint_doctor(fix_hints: bool = typer.Option(False, "--fix-hints")) -> None:
    console.print_json(data=run_doctor(with_fix_hints=fix_hints))


@maint_app.command("integrity-monitor", help="Check integrity status of signed artifacts and bundles.")
def maint_integrity_monitor(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=run_integrity_monitor(_resolve_data_dir(data_dir)))


@maint_app.command("verify-integrity", help="Verify signatures for scan and alerts payloads.")
def maint_verify_integrity(data_dir: str | None = typer.Option(None)) -> None:
    root = _resolve_data_dir(data_dir)
    s, a = load_last_scan(root), load_alerts(root)
    if s.get("integrity_error") or a.get("integrity_error"):
        raise typer.Exit(code=2)
    print("[green]Integrity verification passed.[/green]")


@maint_app.command("forensics-lite", help="Collect signed local forensic-lite snapshot.")
def maint_forensics_lite(data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    root = _resolve_data_dir(data_dir) or Path.home() / ".pocketsoc"
    print(f"[green]Snapshot created:[/green] {build_forensics_snapshot(root)}")


@maint_app.command("forensics-verify", help="Verify signature of a forensics-lite snapshot file.")
def maint_forensics_verify(snapshot_path: str, data_dir: str | None = typer.Option(None)) -> None:
    if not verify_forensics_snapshot(Path(snapshot_path), _resolve_data_dir(data_dir)):
        raise typer.Exit(code=2)
    print("[green]Forensics snapshot signature valid.[/green]")


@maint_app.command("history-prune", help="Prune scan history by age and/or max entries.")
def maint_history_prune(data_dir: str | None = typer.Option(None), days: int | None = typer.Option(None), max_scans: int | None = typer.Option(None), dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    if dry_run:
        hist = load_scan_history(_resolve_data_dir(data_dir))
        console.print_json(data={"dry_run": True, "current_entries": len(hist), "days": days, "max_scans": max_scans})
        return
    guard_mutation()
    print(f"[green]History pruned. Entries kept:[/green] {prune_history(_resolve_data_dir(data_dir), days=days, max_scans=max_scans)}")


@maint_app.command("archive-rotate", help="Compress and sign scan history archive.")
def maint_archive_rotate(data_dir: str | None = typer.Option(None), dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    if dry_run:
        console.print_json(data={"dry_run": True, "would_archive": "scan-history.jsonl"})
        return
    guard_mutation()
    out = rotate_history_archive(_resolve_data_dir(data_dir))
    print(f"[green]Archive created:[/green] {out}" if out else "[yellow]No history to archive.[/yellow]")


@maint_app.command("schedule-install", help="Install local scheduled scan script and metadata.")
def maint_schedule_install(data_dir: str | None = typer.Option(None), interval: str = typer.Option("6h")) -> None:
    guard_mutation()
    print(f"[green]Schedule installed:[/green] {install_schedule(interval, _resolve_data_dir(data_dir))}")


@config_app.command("init", help="Create/overwrite threshold configuration presets.")
def config_init(data_dir: str | None = typer.Option(None), force: bool = typer.Option(False), profile: Literal["balanced", "strict", "battery-saver"] = typer.Option("balanced")) -> None:
    guard_mutation()
    print(f"[green]Config ready:[/green] {write_default_config(_resolve_data_dir(data_dir), force=force, profile=profile)}")


@config_app.command("rules", help="Create/overwrite custom rule definitions.")
def config_rules(data_dir: str | None = typer.Option(None), force: bool = typer.Option(False)) -> None:
    guard_mutation()
    print(f"[green]Rules ready:[/green] {write_default_rules(_resolve_data_dir(data_dir), force=force)}")


@config_app.command("policy", help="Create local compliance policy template.")
def config_policy(data_dir: str | None = typer.Option(None), force: bool = typer.Option(False)) -> None:
    guard_mutation()
    print(f"[green]Policy ready:[/green] {write_default_policy(_resolve_data_dir(data_dir), force=force)}")


@config_app.command("backup", help="Backup config/rules/policy files.")
def config_backup_cmd(data_dir: str | None = typer.Option(None)) -> None:
    print(f"[green]Backup created:[/green] {backup_config(_resolve_data_dir(data_dir))}")


@config_app.command("restore", help="Restore config/rules/policy files.")
def config_restore_cmd(data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    console.print_json(data={"restored": restore_config(_resolve_data_dir(data_dir))})


@config_app.command("deps-verify", help="Validate dependency lock file format and pinning style.")
def config_deps_verify(lockfile: str = typer.Option("requirements-lock.txt")) -> None:
    console.print_json(data=verify_lock(Path(lockfile)))


@config_app.command("suppress-add", help="Add suppression pattern with optional expiration timestamp.")
def config_suppress_add(pattern: str, expires_at: str = typer.Option(""), data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    rule = {"pattern": pattern, "expires_at": expires_at}
    print(f"[green]Suppression added:[/green] {add_suppression(rule, _resolve_data_dir(data_dir))}")


@config_app.command("suppress-list", help="List current suppression rules.")
def config_suppress_list(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data={"suppressions": list_suppressions(_resolve_data_dir(data_dir))})


@config_app.command("suppress-remove", help="Remove suppression rule by 1-based index.")
def config_suppress_remove(index: int, data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    console.print_json(data=remove_suppression(index, _resolve_data_dir(data_dir)))


@config_app.command("autofix-safe", help="Apply non-destructive local bootstrap fixes.")
def config_autofix_safe(data_dir: str | None = typer.Option(None), dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    if dry_run:
        console.print_json(data={"dry_run": True, "would_fix": ["config.json", "rules.json"]})
        return
    guard_mutation()
    console.print_json(data=run_autofix_safe(_resolve_data_dir(data_dir)))


if __name__ == "__main__":
    app()
