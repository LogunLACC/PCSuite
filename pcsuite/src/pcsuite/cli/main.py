import typer
from rich.console import Console
from pcsuite.cli import clean, startup, services, tasks, optimize, security, schedule, process

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

if __name__ == "__main__":
	app()
