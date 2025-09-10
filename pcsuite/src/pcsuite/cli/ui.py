import typer
from rich.console import Console

app = typer.Typer(help="Launch UI frontends")
console = Console()


@app.command()
def gui():
    """Launch the Tkinter GUI."""
    try:
        from pcsuite.ui.gui.app import launch_gui
        launch_gui()
    except Exception as e:
        console.print(f"[red]Failed to launch GUI:[/] {e}")

