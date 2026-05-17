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
from .backup_verify import verify_backup
from .baseline import create_baseline, diff_baseline, load_baseline
from .bundle import build_incident_bundle
from .bundle_sign import sign_bundle, verify_bundle
from .comment_templates import TEMPLATES
from .config import load_threshold_config, write_default_config
from .configio import backup_config, restore_config
from .crypto_zip import decrypt_file
from .deps import verify_lock
from .doctor import run_doctor
from .evidence_chain import verify_chain
from .explain import explain_alert
from .exporters import export_siem
from .forensics import build_forensics_snapshot
from .forensics_verify import verify_forensics_snapshot
from .incident_pack import export_incident_pack
from .integrity_monitor import run_integrity_monitor
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
from .output.render import (
    render_alerts,
    render_dashboard_summary,
    render_scan,
    render_trends,
)
from .policy import eval_policy, write_default_policy
from .policy_simulator import simulate_policies
from .quality_gate import run_quality_gate
from .readonly import guard_mutation
from .redaction import redact_scan_data
from .release_notes import generate_release_notes
from .report_diff import diff_scans, load_scan_file
from .rules import write_default_rules
from .scanner import run_scan, scan_plan
from .scheduler import install_schedule
from .search import global_search
from .sla_dashboard import build_sla_dashboard
from .suppress import add_suppression
from .suppress_manage import list_suppressions, remove_suppression
from .timeline import build_timeline
from .triage import upsert_alert_state
from .triage_analytics import triage_stats
from .triage_templates import apply_template
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


@scan_app.command("plan")
def scan_plan_cmd(
    profile: Literal["quick", "standard", "deep"] = typer.Option("standard"),
    resource_profile: Literal["low", "balanced", "high"] = typer.Option("balanced"),
) -> None:
    console.print_json(data=scan_plan(profile, resource_profile))


@scan_app.command("run")
def scan_run(
    data_dir: str | None = typer.Option(None),
    profile: Literal["quick", "standard", "deep"] = typer.Option("standard"),
    resource_profile: Literal["low", "balanced", "high"] = typer.Option("balanced"),
    time_profile: Literal["auto", "day", "night"] = typer.Option("auto"),
    since_last: bool = typer.Option(False),
    parallel: bool = typer.Option(False),
    timeout: int = typer.Option(60),
    quiet: bool = typer.Option(False),
    output: Literal["table", "json", "ndjson"] = typer.Option("table"),
    fail_on_alert: Literal["none", "low", "medium", "high"] = typer.Option("none"),
    redact: bool = typer.Option(False),
    notify: bool = typer.Option(True),
) -> None:
    root = _resolve_data_dir(data_dir)
    thresholds = load_threshold_config(root)
    hist = load_scan_history(root)
    result = run_scan(
        thresholds,
        profile=profile,
        rules_data_dir=root,
        history=hist,
        since_last=since_last,
        parallel=parallel,
        timeout_seconds=timeout,
        resource_profile=resource_profile,
    )
    if time_profile in ("auto", "night"):
        result.risk_score += 1
    save_scan(result, root)
    save_alerts(result, root)
    scan_payload, alerts_payload = load_last_scan(root), load_alerts(root)
    if redact:
        scan_payload, alerts_payload = redact_scan_data(scan_payload, alerts_payload)
    if notify:
        notify_if_needed(
            alerts_payload.get("risk_score", 0),
            any(a.get("severity") == "high" for a in alerts_payload.get("alerts", [])),
        )
    if not quiet:
        if output == "json":
            console.print_json(data={"scan": scan_payload, "alerts": alerts_payload})
        elif output == "ndjson":
            typer.echo(json.dumps(scan_payload))
            typer.echo(json.dumps(alerts_payload))
        else:
            from pocketsoc.models import Alert, CheckResult, ScanResult

            hydrated = ScanResult(
                scan_payload.get("timestamp", "n/a"),
                [CheckResult(**c) for c in scan_payload.get("checks", [])],
                [Alert(**a) for a in alerts_payload.get("alerts", [])],
                alerts_payload.get("risk_score", calculate_risk_score([])),
            )
            render_scan(hydrated)
            render_alerts(hydrated)
    _exit_on_alert_threshold(alerts_payload, fail_on_alert)


@scan_app.command("watch")
def scan_watch(
    data_dir: str | None = typer.Option(None),
    interval: int = typer.Option(60),
    profile: Literal["quick", "standard", "deep"] = typer.Option("standard"),
) -> None:
    while True:
        scan_run(data_dir=data_dir, profile=profile, quiet=False, output="table")
        time.sleep(max(5, interval))


@scan_app.command("dashboard")
def scan_dashboard(data_dir: str | None = typer.Option(None)) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data = load_last_scan(root)
    from pocketsoc.models import Alert, CheckResult, ScanResult

    hydrated = ScanResult(
        scan_data.get("timestamp", "n/a"),
        [CheckResult(**c) for c in scan_data.get("checks", [])],
        [Alert(**a) for a in scan_data.get("alerts", [])],
        scan_data.get("risk_score", 0),
    )
    render_dashboard_summary(hydrated)
    render_scan(hydrated)


@scan_app.command("alerts")
def scan_alerts(
    data_dir: str | None = typer.Option(None),
    as_json: bool = typer.Option(True, "--json/--table"),
    redact: bool = typer.Option(False),
) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data, payload = load_last_scan(root), load_alerts(root)
    if redact:
        scan_data, payload = redact_scan_data(scan_data, payload)
    if as_json:
        console.print_json(data=payload)
        return
    from pocketsoc.models import Alert, CheckResult, ScanResult

    render_alerts(
        ScanResult(
            payload.get("timestamp", "n/a"),
            [CheckResult(**c) for c in scan_data.get("checks", [])],
            [Alert(**a) for a in payload.get("alerts", [])],
            payload.get("risk_score", 0),
        )
    )


@scan_app.command("explain-alert")
def scan_explain_alert(
    alert_id: str, data_dir: str | None = typer.Option(None)
) -> None:
    console.print_json(data=explain_alert(alert_id, _resolve_data_dir(data_dir)))


@scan_app.command("search")
def scan_search(
    query: str,
    since: str = typer.Option("7d"),
    data_dir: str | None = typer.Option(None),
) -> None:
    console.print_json(
        data=global_search(
            query=query, since=since, data_dir=_resolve_data_dir(data_dir)
        )
    )


@scan_app.command("triage-apply")
def scan_triage_apply(
    alert_id: str,
    severity: str,
    status: str = typer.Option("investigating"),
    owner: str = typer.Option(""),
    comment: str = typer.Option(""),
    source_check: str = typer.Option(""),
    data_dir: str | None = typer.Option(None),
) -> None:
    guard_mutation()
    console.print_json(
        data=upsert_alert_state(
            alert_id,
            severity,
            status=status,
            owner=owner,
            comment=comment,
            source_check=source_check,
            data_dir=_resolve_data_dir(data_dir),
        )
    )


@scan_app.command("triage-template")
def scan_triage_template(
    alert_id: str,
    severity: str,
    template: str = typer.Option("investigation_started"),
    status: str = typer.Option("investigating"),
    owner: str = typer.Option(""),
    source_check: str = typer.Option(""),
    data_dir: str | None = typer.Option(None),
) -> None:
    guard_mutation()
    console.print_json(
        data=apply_template(
            alert_id=alert_id,
            severity=severity,
            template_key=template,
            status=status,
            owner=owner,
            source_check=source_check,
            data_dir=_resolve_data_dir(data_dir),
        )
    )


@report_app.command("md")
def report_md(
    data_dir: str | None = typer.Option(None),
    redact: bool = typer.Option(False),
    report_format: Literal["full", "executive"] = typer.Option("full", "--format"),
    compare_baseline: bool = typer.Option(False, "--compare-baseline"),
) -> None:
    root = _resolve_data_dir(data_dir)
    scan_data, alerts = load_last_scan(root), load_alerts(root)
    if redact:
        scan_data, alerts = redact_scan_data(scan_data, alerts)
    baseline_diff_data = (
        diff_baseline(scan_data, load_baseline(root)) if compare_baseline else None
    )
    print(
        f"[green]Report written:[/green] {export_markdown_report(scan_data, alerts, root, report_format=report_format, compare_baseline=baseline_diff_data)}"
    )


@report_app.command("diff")
def report_diff(scan_a: str, scan_b: str) -> None:
    console.print_json(
        data=diff_scans(load_scan_file(Path(scan_a)), load_scan_file(Path(scan_b)))
    )


@report_app.command("timeline")
def report_timeline(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data={"events": build_timeline(_resolve_data_dir(data_dir))})


@report_app.command("sla")
def report_sla(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=build_sla_dashboard(_resolve_data_dir(data_dir)))


@report_app.command("triage-analytics")
def report_triage_analytics(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=triage_stats(_resolve_data_dir(data_dir)))


@report_app.command("trends")
def report_trends(
    data_dir: str | None = typer.Option(None), csv: bool = typer.Option(False, "--csv")
) -> None:
    root = _resolve_data_dir(data_dir)
    hist = load_scan_history(root)
    render_trends(hist)
    if csv:
        print(f"[green]CSV exported:[/green] {export_trends_csv(hist, root)}")


@report_app.command("export")
def report_export(
    data_dir: str | None = typer.Option(None),
    fmt: Literal["cef", "syslog-json"] = typer.Option("syslog-json"),
) -> None:
    print(
        f"[green]Export written:[/green] {export_siem(_resolve_data_dir(data_dir), fmt)}"
    )


@report_app.command("audit-export")
def report_audit_export(
    data_dir: str | None = typer.Option(None),
    fmt: Literal["json", "csv"] = typer.Option("json"),
) -> None:
    print(
        f"[green]Audit export written:[/green] {export_audit(_resolve_data_dir(data_dir), fmt=fmt)}"
    )


@report_app.command("incident-pack")
def report_incident_pack(data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    print(
        f"[green]Incident pack written:[/green] {export_incident_pack(_resolve_data_dir(data_dir))}"
    )


@report_app.command("bundle")
def report_bundle(
    data_dir: str | None = typer.Option(None),
    since: str = typer.Option("24h"),
    redact: bool = typer.Option(False, "--redact"),
    sign: bool = typer.Option(True, "--sign/--no-sign"),
    encrypt_password: str = typer.Option("", "--encrypt-password"),
) -> None:
    guard_mutation()
    root = _resolve_data_dir(data_dir)
    _ = since
    out = build_incident_bundle(root, redact=redact, encrypt_password=encrypt_password)
    if sign:
        print(
            f"[green]Bundle created:[/green] {out}\n[green]Signature:[/green] {sign_bundle(out, root)}"
        )
    else:
        print(f"[green]Bundle created:[/green] {out}")


@report_app.command("bundle-decrypt")
def report_bundle_decrypt(
    bundle_path: str, password: str = typer.Option(..., "--password")
) -> None:
    guard_mutation()
    print(
        f"[green]Decrypted bundle:[/green] {decrypt_file(Path(bundle_path), password)}"
    )


@report_app.command("bundle-verify")
def report_bundle_verify(
    bundle_path: str, data_dir: str | None = typer.Option(None)
) -> None:
    if not verify_bundle(Path(bundle_path), _resolve_data_dir(data_dir)):
        raise typer.Exit(code=2)
    print("[green]Bundle signature valid.[/green]")


@baseline_app.command("create")
def baseline_create_cmd(
    data_dir: str | None = typer.Option(None),
    profile: Literal["quick", "standard", "deep"] = typer.Option("standard"),
    device_id: str = typer.Option("local-device"),
) -> None:
    guard_mutation()
    print(
        f"[green]Baseline saved:[/green] {create_baseline(_resolve_data_dir(data_dir), profile, device_id=device_id)}"
    )


@baseline_app.command("diff")
def baseline_diff_cmd(
    data_dir: str | None = typer.Option(None),
    tolerance: int = typer.Option(0),
    explain: bool = typer.Option(False),
) -> None:
    root = _resolve_data_dir(data_dir)
    console.print_json(
        data=diff_baseline(
            load_last_scan(root),
            load_baseline(root),
            tolerance=tolerance,
            explain=explain,
        )
    )


@baseline_app.command("policy-eval")
def baseline_policy_eval(
    data_dir: str | None = typer.Option(None),
    enforce: bool = typer.Option(False, "--enforce"),
    baseline_aware: bool = typer.Option(False, "--baseline-aware"),
) -> None:
    res = eval_policy(_resolve_data_dir(data_dir), baseline_aware=baseline_aware)
    console.print_json(data=res)
    if enforce and not res.get("compliant", False):
        raise typer.Exit(code=2)


@baseline_app.command("policy-sim")
def baseline_policy_sim(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=simulate_policies(_resolve_data_dir(data_dir)))


@api_app.command("serve")
def api_serve(
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8787),
    data_dir: str | None = typer.Option(None),
) -> None:
    serve_api(host, port, _resolve_data_dir(data_dir))


@api_app.command("key-rotate")
def api_key_rotate_cmd(data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    print(
        f"[green]API token rotated:[/green] {rotate_api_token(_resolve_data_dir(data_dir))}"
    )


@api_app.command("ui-build")
def api_ui_build(data_dir: str | None = typer.Option(None)) -> None:
    print(f"[green]UI generated:[/green] {write_web_ui(_resolve_data_dir(data_dir))}")


@maint_app.command("doctor")
def maint_doctor(fix_hints: bool = typer.Option(False, "--fix-hints")) -> None:
    console.print_json(data=run_doctor(with_fix_hints=fix_hints))


@maint_app.command("integrity-monitor")
def maint_integrity_monitor(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=run_integrity_monitor(_resolve_data_dir(data_dir)))


@maint_app.command("evidence-verify")
def maint_evidence_verify(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=verify_chain(_resolve_data_dir(data_dir)))


@maint_app.command("verify-integrity")
def maint_verify_integrity(data_dir: str | None = typer.Option(None)) -> None:
    root = _resolve_data_dir(data_dir)
    s, a = load_last_scan(root), load_alerts(root)
    if s.get("integrity_error") or a.get("integrity_error"):
        raise typer.Exit(code=2)
    print("[green]Integrity verification passed.[/green]")


@maint_app.command("forensics-lite")
def maint_forensics_lite(data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    root = _resolve_data_dir(data_dir) or Path.home() / ".pocketsoc"
    print(f"[green]Snapshot created:[/green] {build_forensics_snapshot(root)}")


@maint_app.command("forensics-verify")
def maint_forensics_verify(
    snapshot_path: str, data_dir: str | None = typer.Option(None)
) -> None:
    if not verify_forensics_snapshot(Path(snapshot_path), _resolve_data_dir(data_dir)):
        raise typer.Exit(code=2)
    print("[green]Forensics snapshot signature valid.[/green]")


@maint_app.command("history-prune")
def maint_history_prune(
    data_dir: str | None = typer.Option(None),
    days: int | None = typer.Option(None),
    max_scans: int | None = typer.Option(None),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if dry_run:
        hist = load_scan_history(_resolve_data_dir(data_dir))
        console.print_json(
            data={
                "dry_run": True,
                "current_entries": len(hist),
                "days": days,
                "max_scans": max_scans,
            }
        )
        return
    guard_mutation()
    print(
        f"[green]History pruned. Entries kept:[/green] {prune_history(_resolve_data_dir(data_dir), days=days, max_scans=max_scans)}"
    )


@maint_app.command("archive-rotate")
def maint_archive_rotate(
    data_dir: str | None = typer.Option(None),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if dry_run:
        console.print_json(
            data={"dry_run": True, "would_archive": "scan-history.jsonl"}
        )
        return
    guard_mutation()
    out = rotate_history_archive(_resolve_data_dir(data_dir))
    print(
        f"[green]Archive created:[/green] {out}"
        if out
        else "[yellow]No history to archive.[/yellow]"
    )


@maint_app.command("schedule-install")
def maint_schedule_install(
    data_dir: str | None = typer.Option(None), interval: str = typer.Option("6h")
) -> None:
    guard_mutation()
    print(
        f"[green]Schedule installed:[/green] {install_schedule(interval, _resolve_data_dir(data_dir))}"
    )


@maint_app.command("release-notes")
def maint_release_notes(changelog: str = typer.Option("CHANGELOG.md")) -> None:
    typer.echo(generate_release_notes(Path(changelog)))


@maint_app.command("quality-gate")
def maint_quality_gate(repo_root: str = typer.Option(".")) -> None:
    result = run_quality_gate(Path(repo_root).resolve())
    console.print_json(data=result)
    if not result.get("ok", False):
        raise typer.Exit(code=2)


@maint_app.command("self-check")
def maint_self_check(data_dir: str | None = typer.Option(None)) -> None:
    from .self_check import run_self_check

    res = run_self_check(_resolve_data_dir(data_dir))
    console.print_json(data=res)
    if not res.get("ok", False):
        raise typer.Exit(code=2)


@config_app.command("init")
def config_init(
    data_dir: str | None = typer.Option(None),
    force: bool = typer.Option(False),
    profile: Literal["balanced", "strict", "battery-saver"] = typer.Option("balanced"),
) -> None:
    guard_mutation()
    print(
        f"[green]Config ready:[/green] {write_default_config(_resolve_data_dir(data_dir), force=force, profile=profile)}"
    )


@config_app.command("rules")
def config_rules(
    data_dir: str | None = typer.Option(None), force: bool = typer.Option(False)
) -> None:
    guard_mutation()
    print(
        f"[green]Rules ready:[/green] {write_default_rules(_resolve_data_dir(data_dir), force=force)}"
    )


@config_app.command("policy")
def config_policy(
    data_dir: str | None = typer.Option(None),
    force: bool = typer.Option(False),
    pack: Literal["home-lab", "strict-mobile", "low-power"] = typer.Option(
        "home-lab", "--pack"
    ),
) -> None:
    guard_mutation()
    print(
        f"[green]Policy ready:[/green] {write_default_policy(_resolve_data_dir(data_dir), force=force, pack=pack)}"
    )


@config_app.command("comment-templates")
def config_comment_templates() -> None:
    console.print_json(data={"templates": TEMPLATES})


@config_app.command("backup")
def config_backup_cmd(data_dir: str | None = typer.Option(None)) -> None:
    print(
        f"[green]Backup created:[/green] {backup_config(_resolve_data_dir(data_dir))}"
    )


@config_app.command("backup-verify")
def config_backup_verify(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(data=verify_backup(_resolve_data_dir(data_dir)))


@config_app.command("restore")
def config_restore_cmd(data_dir: str | None = typer.Option(None)) -> None:
    guard_mutation()
    console.print_json(data={"restored": restore_config(_resolve_data_dir(data_dir))})


@config_app.command("deps-verify")
def config_deps_verify(lockfile: str = typer.Option("requirements-lock.txt")) -> None:
    console.print_json(data=verify_lock(Path(lockfile)))


@config_app.command("suppress-add")
def config_suppress_add(
    pattern: str,
    expires_at: str = typer.Option(""),
    data_dir: str | None = typer.Option(None),
) -> None:
    guard_mutation()
    print(
        f"[green]Suppression added:[/green] {add_suppression({'pattern': pattern, 'expires_at': expires_at}, _resolve_data_dir(data_dir))}"
    )


@config_app.command("suppress-list")
def config_suppress_list(data_dir: str | None = typer.Option(None)) -> None:
    console.print_json(
        data={"suppressions": list_suppressions(_resolve_data_dir(data_dir))}
    )


@config_app.command("suppress-remove")
def config_suppress_remove(
    index: int, data_dir: str | None = typer.Option(None)
) -> None:
    guard_mutation()
    console.print_json(data=remove_suppression(index, _resolve_data_dir(data_dir)))


@config_app.command("autofix-safe")
def config_autofix_safe(
    data_dir: str | None = typer.Option(None),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if dry_run:
        console.print_json(
            data={"dry_run": True, "would_fix": ["config.json", "rules.json"]}
        )
        return
    guard_mutation()
    console.print_json(data=run_autofix_safe(_resolve_data_dir(data_dir)))


if __name__ == "__main__":
    app()
