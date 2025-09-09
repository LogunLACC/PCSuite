import typer
from rich.console import Console
from rich.table import Table
import psutil
from pcsuite.core import shell

app = typer.Typer(help="Security checks: Defender and Firewall status")
console = Console()


@app.command()
def check():
    table = Table(title="Security Status")
    table.add_column("Component"); table.add_column("Status")
    # Defender service
    try:
        svc = psutil.win_service_get("WinDefend").as_dict()
        table.add_row("Defender (WinDefend)", svc.get("status", "unknown"))
    except Exception:
        table.add_row("Defender (WinDefend)", "not found")

    # Firewall
    code, out, err = shell.cmdline("netsh advfirewall show allprofiles")
    if code == 0 and ("State" in out):
        # Try to extract 'ON'/'OFF'
        states = []
        for line in out.splitlines():
            if line.strip().startswith("State"):
                states.append(line.split()[-1])
        table.add_row("Firewall (All Profiles)", ", ".join(states) or "unknown")
    else:
        table.add_row("Firewall", f"error: {err}" if err else "unknown")

    console.print(table)
