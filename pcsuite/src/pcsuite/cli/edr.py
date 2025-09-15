import json
import typer
from rich.console import Console
from rich.table import Table

from pcsuite.security import edr


app = typer.Typer(help="EDR prototype: status, isolation, triage, scans")
console = Console()


@app.command()
def status():
    data = edr.status()
    table = Table(title="EDR Status")
    table.add_column("Field"); table.add_column("Value")
    for k in ("product", "version", "os", "enrolled"):
        table.add_row(k, str(data.get(k)))
    fw = data.get("firewall", {})
    table.add_row("Firewall", ", ".join([f"{k}:{v}" for k, v in fw.items()]))
    console.print(table)


@app.command()
def isolate(
    enable: bool = typer.Option(..., help="Enable (True) or disable (False) network isolation"),
    dry_run: bool = typer.Option(True, help="Simulate; no changes"),
):
    res = edr.isolate(enable=enable, dry_run=dry_run)
    if res.get("ok") and res.get("dry_run"):
        console.print("[yellow]Dry-run[/]: firewall state change planned")
    elif res.get("ok"):
        console.print("[green]Isolation updated[/]")
    else:
        console.print("[red]Isolation failed[/]")


@app.command()
def triage():
    t = edr.quick_triage_summary()
    table = Table(title="Quick Triage")
    table.add_column("Metric"); table.add_column("Value")
    for k, v in t.items():
        table.add_row(k, str(v))
    console.print(table)


@app.command("scan-file")
def scan_file(path: str):
    data = edr.scan_file(path)
    console.print_json(json.dumps(data))


@app.command("ports")
def list_ports(limit: int = typer.Option(100, help="Max entries to show")):
    ports = edr.list_listening_ports(limit=limit)
    table = Table(title="Listening Ports (EDR)")
    table.add_column("Proto"); table.add_column("Local Address"); table.add_column("PID"); table.add_column("Process")
    for p in ports:
        table.add_row(p.get("proto",""), p.get("laddr",""), str(p.get("pid","")), p.get("proc",""))
    console.print(table)


@app.command("detect")
def detect(
    rules: str = typer.Option(..., help="Path to rule file (.yml) or directory"),
    limit: int = typer.Option(200, help="Max events to evaluate"),
):
    res = edr.detect(rules_path=rules, limit=limit)
    table = Table(title="EDR Rule Matches")
    table.add_column("Rule"); table.add_column("Matches"); table.add_column("Sample Field")
    for m in res.get("matches", []):
        samp = m.get("sample", {})
        field = (samp.get("Message") or str(list(samp.keys())[:1])) if isinstance(samp, dict) else ""
        table.add_row(m.get("rule",""), str(m.get("count",0)), str(field)[:60])
    console.print(table)


@app.command("quarantine-file")
def quarantine_file(
    path: str,
    dry_run: bool = typer.Option(True, help="Simulate; do not move file"),
    yes: bool = typer.Option(False, help="Skip confirmation when not dry-run"),
):
    if not dry_run and not yes:
        if not typer.confirm(f"Move '{path}' into quarantine? (rollback available)", default=False):
            console.print("[yellow]Aborted by user[/]")
            return
    res = edr.quarantine_file(path, dry_run=dry_run)
    if res.get("dry_run"):
        console.print("[yellow]Dry-run[/]: would quarantine file")
    else:
        console.print("[green]Quarantined[/]")
    console.print_json(json.dumps(res))
