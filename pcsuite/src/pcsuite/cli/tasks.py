import typer
from rich.console import Console
from rich.table import Table
from pcsuite.core import shell

app = typer.Typer(help="Scheduled tasks via schtasks (read-only)")
console = Console()


@app.command()
def list():
    code, out, err = shell.cmdline("schtasks /query /fo LIST /v")
    if code != 0:
        console.print(f"[red]schtasks failed:[/] {err}")
        return
    # Very rough parse: split on blank lines per task
    entries = [blk for blk in out.splitlines() if blk.strip()]
    # For compactness, run a simpler CSV query
    code, out, err = shell.cmdline("schtasks /query /fo CSV")
    if code != 0:
        console.print(f"[red]schtasks CSV failed:[/] {err}")
        return
    table = Table(title="Scheduled Tasks")
    table.add_column("TaskName"); table.add_column("NextRunTime"); table.add_column("Status")
    # skip header
    for i, line in enumerate(out.splitlines()):
        if i == 0:
            continue
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) >= 3:
            table.add_row(parts[0], parts[1], parts[2])
    console.print(table)
