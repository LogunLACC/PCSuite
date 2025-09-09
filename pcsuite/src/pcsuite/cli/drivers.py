import typer
from rich.console import Console
from rich.table import Table
from pcsuite.core import shell

app = typer.Typer(help="Driver tools: list installed and trigger Windows Update scan/install")
console = Console()


@app.command()
def list():
    """List installed third-party drivers via pnputil."""
    code, out, err = shell.cmdline("pnputil /enum-drivers")
    if code != 0:
        console.print(f"[red]pnputil failed:[/] {err}")
        return
    table = Table(title="Installed Drivers (pnputil)")
    table.add_column("Published Name"); table.add_column("Provider"); table.add_column("Class")
    pub = prov = cls = None
    for line in out.splitlines():
        if ":" in line:
            k, v = [x.strip() for x in line.split(":", 1)]
            if k.lower().startswith("published name"):
                if pub:
                    table.add_row(pub or "", prov or "", cls or "")
                pub = v; prov = cls = None
            elif k.lower().startswith("driver package provider"):
                prov = v
            elif k.lower().startswith("class"):
                cls = v
    if pub:
        table.add_row(pub or "", prov or "", cls or "")
    console.print(table)


@app.command()
def scan():
    """Trigger Windows Update scan (includes drivers offered via WU)."""
    code, out, err = shell.pwsh("(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow(); 'OK'")
    if code == 0:
        console.print("[green]Scan triggered[/]")
    else:
        console.print(f"[red]Scan failed:[/] {err}")


@app.command()
def update(
    dry_run: bool = typer.Option(True, help="Simulate install (default)"),
    yes: bool = typer.Option(False, help="Skip confirmation for non-dry-run"),
):
    """Attempt to start Windows Update download/install cycle.

    Note: Real installation may require admin and interactive consent.
    """
    if dry_run:
        console.print("[yellow]Dry-run:[/] Would invoke Windows Update install (UsoClient)")
        return
    if not yes and not typer.confirm("Start Windows Update download/install now?", default=False):
        console.print("[yellow]Aborted by user[/]")
        return
    code, out, err = shell.cmdline("UsoClient StartScan && UsoClient StartDownload && UsoClient StartInstall")
    if code == 0:
        console.print("[green]Windows Update cycle started[/]")
    else:
        console.print(f"[red]Update failed:[/] {err}")
