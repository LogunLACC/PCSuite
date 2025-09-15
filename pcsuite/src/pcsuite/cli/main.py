import typer
from rich.console import Console
from pcsuite.cli import (
    clean,
    startup,
    services,
    tasks,
    optimize,
    security,
    schedule,
    process,
    drivers,
    registry,
    system,
    ui,
    edr,
)

app = typer.Typer(add_completion=False)
console = Console()

app.add_typer(clean.app, name="clean")
app.add_typer(startup.app, name="startup")
app.add_typer(services.app, name="services")
app.add_typer(tasks.app, name="tasks")
app.add_typer(optimize.app, name="optimize")
app.add_typer(security.app, name="security")
app.add_typer(schedule.app, name="schedule")
app.add_typer(process.app, name="process")
app.add_typer(drivers.app, name="drivers")
app.add_typer(registry.app, name="registry")
app.add_typer(system.app, name="system")
app.add_typer(ui.app, name="ui")
app.add_typer(edr.app, name="edr")

if __name__ == "__main__":
	app()
