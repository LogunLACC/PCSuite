import typer
from rich.table import Table
from rich.console import Console
import psutil

app = typer.Typer(help="Process tools: list and kill (supports --dry-run)")
console = Console()


@app.command()
def list(limit: int = typer.Option(15, help="Max processes by memory")):
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name", "memory_info", "cpu_percent"]):
        try:
            mi = p.info.get("memory_info")
            rss = getattr(mi, "rss", 0) if mi else 0
            procs.append((rss, p))
        except Exception:
            continue
    procs.sort(key=lambda x: x[0], reverse=True)
    table = Table(title="Top Processes by RSS")
    table.add_column("PID"); table.add_column("Name"); table.add_column("RSS")
    for rss, p in procs[:limit]:
        table.add_row(str(p.pid), p.info.get("name", ""), f"{rss:,}")
    console.print(table)


@app.command()
def kill(
    pid: int = typer.Option(..., "--pid", "-p", help="Process ID to terminate"),
    dry_run: bool = typer.Option(False, help="Simulate kill"),
    yes: bool = typer.Option(False, help="Skip confirmation for non-dry-run"),
):
    try:
        p = psutil.Process(pid)
        if dry_run:
            console.print(f"[yellow]Dry-run:[/] Would terminate PID {pid} ({p.name()})")
            return
        if not yes:
            if not typer.confirm(f"Terminate PID {pid} ({p.name()})?", default=False):
                console.print("[yellow]Aborted by user[/]")
                return
        p.terminate()
        console.print(f"[green]Terminated PID {pid}[/]")
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
