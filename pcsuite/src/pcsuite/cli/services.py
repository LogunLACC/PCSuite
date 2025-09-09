import typer
from rich.table import Table
from rich.console import Console
import psutil

app = typer.Typer(help="Windows services helper (list only; safe by default)")
console = Console()


@app.command()
def list(status: str = typer.Option("", help="Filter: running|stopped|")):
    """List Windows services with status and display name."""
    table = Table(title="Services")
    table.add_column("Name"); table.add_column("Display"); table.add_column("Status")
    for s in psutil.win_service_iter():
        try:
            info = s.as_dict()
            st = info.get("status", "?")
            if status and st != status:
                continue
            table.add_row(info.get("name", ""), info.get("display_name", ""), st)
        except Exception:
            continue
    console.print(table)
