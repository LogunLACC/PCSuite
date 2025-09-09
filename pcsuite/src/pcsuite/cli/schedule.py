import typer
from rich.console import Console
from pcsuite.core import shell

app = typer.Typer(help="Simple wrappers for scheduling (schtasks)")
console = Console()


@app.command()
def list():
    from pcsuite.cli import tasks as tasks_cli
    # Reuse tasks list
    tasks_cli.list()


@app.command()
def create(
    name: str = typer.Option(..., "--name", "-n", help="Task path/name, e.g., \\MyTasks\\PCSuiteCleanup"),
    when: str = typer.Option(..., "--when", "-w", help="Trigger: MINUTE|HOURLY|DAILY|WEEKLY|ONLOGON|ONIDLE|ONSTART"),
    command: str = typer.Option(..., "--command", "-c", help="Command to execute (quoted)"),
    dry_run: bool = typer.Option(False, help="Simulate; no changes"),
    yes: bool = typer.Option(False, help="Skip confirmation for non-dry-run"),
):
    """Create a scheduled task.

    - name: Task path/name, e.g., \MyTasks\PCSuiteCleanup
    - when: Trigger, e.g., DAILY or ONLOGON
    - command: Command to execute (quoted)
    """
    sch = f'schtasks /create /tn "{name}" /sc {when} /tr "{command}" /rl HIGHEST /f'
    if dry_run:
        console.print(f"[yellow]Dry-run:[/] {sch}")
        return
    if not yes and not typer.confirm(f"Create scheduled task '{name}'?", default=False):
        console.print("[yellow]Aborted by user[/]")
        return
    code, out, err = shell.cmdline(sch)
    if code != 0:
        console.print(f"[red]Error:[/] {err}")
    else:
        console.print("[green]Task created[/]")


@app.command()
def delete(
    name: str = typer.Option(..., "--name", "-n", help="Task path/name, e.g., \\MyTasks\\PCSuiteCleanup"),
    dry_run: bool = typer.Option(False, help="Simulate; no changes"),
    yes: bool = typer.Option(False, help="Skip confirmation for non-dry-run"),
):
    sch = f'schtasks /delete /tn "{name}" /f'
    if dry_run:
        console.print(f"[yellow]Dry-run:[/] {sch}")
        return
    if not yes and not typer.confirm(f"Delete scheduled task '{name}'?", default=False):
        console.print("[yellow]Aborted by user[/]")
        return
    code, out, err = shell.cmdline(sch)
    if code != 0:
        console.print(f"[red]Error:[/] {err}")
    else:
        console.print("[green]Task deleted[/]")
