import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
import os
import winreg

app = typer.Typer(help="Startup entries (read-only list for HKCU/HKLM and Startup folders)")
console = Console()


def _read_run_key(root, sub):
    items = []
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                    items.append((name, val))
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return items


@app.command()
def list():
    table = Table(title="Startup Entries")
    table.add_column("Source"); table.add_column("Name"); table.add_column("Data")
    # HKCU and HKLM Run keys
    for source, root in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        for name, val in _read_run_key(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"):
            table.add_row(f"{source}\\...\\Run", name, str(val))

    # Startup folders
    for folder_name, env in (("User Startup", "APPDATA"), ("Common Startup", "PROGRAMDATA")):
        try:
            base = Path(Path().home()) if env == "APPDATA" else Path(os.environ.get("PROGRAMDATA", ""))
        except Exception:
            base = None
        path = None
        if env == "APPDATA":
            path = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
        else:
            path = Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"
        if path and path.exists():
            for p in path.iterdir():
                table.add_row(folder_name, p.name, str(p))
    console.print(table)
