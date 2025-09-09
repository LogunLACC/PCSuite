import typer
from rich.console import Console
from rich.table import Table
from pcsuite.core import fs

app = typer.Typer()
console = Console()

@app.command()
def preview(category: str = typer.Option("temp,browser,dumps,do,recycle", help="Comma list")):
	cats = [c.strip() for c in category.split(",") if c.strip()]
	targets = fs.enumerate_targets(cats)
	table = Table(title="Preview: Files to Clean")
	table.add_column("Path"); table.add_column("Size")
	total = 0
	for t in targets:
		table.add_row(t.path, f"{t.size:,}")
		total += t.size
	console.print(table)
	console.print(f"[bold]Total bytes[/]: {total:,}")
	report_path = fs.write_audit_report(targets, action="preview")
	console.print(f"[green]Audit report written:[/] {report_path}")

@app.command()
def run(
	category: str = typer.Option("temp,browser,dumps,do,recycle"),
	dry_run: bool = typer.Option(False, help="Simulate actions; no files moved"),
	yes: bool = typer.Option(False, help="Skip confirmation prompt"),
):
	cats = [c.strip() for c in category.split(",") if c.strip()]
	if not dry_run and not yes:
		preview = fs.enumerate_targets(cats)
		total = sum(t.size for t in preview)
		proceed = typer.confirm(
			f"About to move {len(preview)} files (~{total:,} bytes) to quarantine. Continue?",
			default=False,
		)
		if not proceed:
			console.print("[yellow]Aborted by user[/]")
			return
	res = fs.execute_cleanup(cats, dry_run=dry_run)
	msg = (
		f"Moved: {res['moved']}, Failed: {res['failed']}\n"
		f"[green]Cleanup report:[/] {res['cleanup_report']}\n"
	)
	if dry_run:
		msg += "[yellow]Dry-run: no changes made[/]"
	else:
		msg += f"[yellow]Rollback file:[/] {res['rollback_file']}"
	console.print(msg)

@app.command()
def rollback(
	file: str = typer.Option("", help="Path to reports/rollback_*.json; if empty, use latest"),
	dry_run: bool = typer.Option(False, help="Simulate restore; no files moved"),
	yes: bool = typer.Option(False, help="Skip confirmation prompt"),
):
	if not dry_run and not yes:
		proceed = typer.confirm("Restore files from quarantine back to original locations?", default=False)
		if not proceed:
			console.print("[yellow]Aborted by user[/]")
			return
	res = fs.execute_rollback(file or None, dry_run=dry_run)
	msg = (
		f"Restored: {res['restored']}, Failed: {res['failed']}\n"
		f"[green]Restore report:[/] {res['restore_report']}"
	)
	if dry_run:
		msg += "\n[yellow]Dry-run: no changes made[/]"
	console.print(msg)
