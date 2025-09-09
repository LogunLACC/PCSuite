import typer
from rich.console import Console
from rich.table import Table
from pcsuite.core import registry

app = typer.Typer(help="Registry cleaner: preview, run, rollback (HKCU MRUs)")
console = Console()


@app.command()
def preview():
    data = registry.registry_preview()
    table = Table(title="Registry Clean Preview")
    table.add_column("Key"); table.add_column("Values"); table.add_column("Subkeys")
    for t in data.get("targets", []):
        table.add_row(t["key"], str(len(t.get("values", []))), str(len(t.get("subkeys", []))))
    console.print(table)


@app.command()
def run(
    dry_run: bool = typer.Option(False, help="Simulate; only write report and backups"),
    yes: bool = typer.Option(False, help="Skip confirmation for non-dry-run"),
):
    if not dry_run and not yes:
        if not typer.confirm("Proceed with registry cleanup (backups will be created)?", default=False):
            console.print("[yellow]Aborted by user[/]")
            return
    res = registry.registry_cleanup(dry_run=dry_run)
    if dry_run:
        console.print(f"[yellow]Dry-run:[/] wrote {res['cleanup_report']}")
    else:
        console.print(f"[green]Cleanup report:[/] {res['cleanup_report']}\n[yellow]Rollback file:[/] {res['rollback_file']}")


@app.command()
def rollback(
    file: str = typer.Option("", help="Path to registry_rollback_*.json"),
    dry_run: bool = typer.Option(False),
    yes: bool = typer.Option(False, help="Skip confirmation for non-dry-run"),
):
    if not dry_run and not yes:
        if not typer.confirm("Import registry backups and restore keys?", default=False):
            console.print("[yellow]Aborted by user[/]")
            return
    res = registry.registry_rollback(file or None, dry_run=dry_run)
    console.print(f"Restored: {res['restored']}\n[green]Restore report:[/] {res['restore_report']}")
