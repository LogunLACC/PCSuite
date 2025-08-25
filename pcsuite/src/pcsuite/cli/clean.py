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
def run(category: str = typer.Option("temp,browser,dumps,do,recycle")):
	cats = [c.strip() for c in category.split(",") if c.strip()]
	fs.execute_cleanup(cats)
	console.print("Cleanup complete. See reports/ for audit log.")
