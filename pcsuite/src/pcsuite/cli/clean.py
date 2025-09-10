import enum
import typer
from rich.console import Console
from rich.table import Table
from pcsuite.core import fs

class Scope(str, enum.Enum):
    auto = "auto"
    user = "user"
    all = "all"


app = typer.Typer()
console = Console()

@app.command()
def preview(
    category: str = typer.Option("temp,browser,dumps,do,recycle", help="Comma list"),
    scope: Scope = typer.Option(Scope.auto, help="Scope: auto|user|all"),
):
	cats = [c.strip() for c in category.split(",") if c.strip()]
	targets = fs.enumerate_targets(cats, scope=scope.value)
	table = Table(title="Preview: Files to Clean")
	table.add_column("Path"); table.add_column("Size")
	total = 0
	for t in targets:
		table.add_row(t.path, f"{t.size:,}")
		total += t.size
	console.print(table)
	console.print(f"[bold]Total bytes[/]: {total:,}")
	report_path = fs.write_audit_report(targets, action="preview")
	console.print(f"[green]Audit report written:[/] {report_path}")

@app.command()
def run(
    category: str = typer.Option("temp,browser,dumps,do,recycle"),
    dry_run: bool = typer.Option(False, help="Simulate actions; no files moved"),
    yes: bool = typer.Option(False, help="Skip confirmation prompt"),
    scope: Scope = typer.Option(Scope.auto, help="Scope: auto|user|all"),
):
	cats = [c.strip() for c in category.split(",") if c.strip()]
	if not dry_run and not yes:
		preview = fs.enumerate_targets(cats, scope=scope.value)
		total = sum(t.size for t in preview)
		proceed = typer.confirm(
			f"About to move {len(preview)} files (~{total:,} bytes) to quarantine. Continue?",
			default=False,
		)
		if not proceed:
			console.print("[yellow]Aborted by user[/]")
			return
	res = fs.execute_cleanup(cats, dry_run=dry_run, scope=scope.value)
	msg = (
		f"Moved: {res['moved']}, Failed: {res['failed']}\n"
		f"[green]Cleanup report:[/] {res['cleanup_report']}\n"
	)
	if dry_run:
		msg += "[yellow]Dry-run: no changes made[/]"
	else:
		msg += f"[yellow]Rollback file:[/] {res['rollback_file']}"
	console.print(msg)

@app.command()
def rollback(
	file: str = typer.Option("", help="Path to reports/rollback_*.json; if empty, use latest"),
	dry_run: bool = typer.Option(False, help="Simulate restore; no files moved"),
	yes: bool = typer.Option(False, help="Skip confirmation prompt"),
):
	if not dry_run and not yes:
		proceed = typer.confirm("Restore files from quarantine back to original locations?", default=False)
		if not proceed:
			console.print("[yellow]Aborted by user[/]")
			return
	res = fs.execute_rollback(file or None, dry_run=dry_run)
	msg = (
		f"Restored: {res['restored']}, Failed: {res['failed']}\n"
		f"[green]Restore report:[/] {res['restore_report']}"
	)
	if dry_run:
		msg += "\n[yellow]Dry-run: no changes made[/]"
	console.print(msg)


@app.command()
def purge(
    run: str = typer.Option("", help="Quarantine run to purge (timestamp name or path). Use 'latest' to purge latest."),
    older_than: int = typer.Option(0, help="Purge runs older than N days"),
    all: bool = typer.Option(False, help="Purge all quarantine runs"),
    dry_run: bool = typer.Option(False, help="Show what would be deleted; no changes"),
    yes: bool = typer.Option(False, help="Skip confirmation when not dry-run"),
):
    """Permanently delete quarantined files to actually free disk space.

    Warning: After purge, rollback for those runs is no longer possible.
    """
    # Determine targets for display
    targets = []
    try:
        from pcsuite.core import fs as _fs
        if all:
            targets = _fs.list_quarantine_runs()
        elif older_than and older_than > 0:
            # Grab runs; filter here just for display, fs.purge_quarantine will finalize
            import datetime as _dt
            from pathlib import Path as _Path
            q = _Path(_fs.QUARANTINE_DIR) if hasattr(_fs, 'QUARANTINE_DIR') else None
            runs = _fs.list_quarantine_runs()
            if runs:
                cutoff = _dt.datetime.now() - _dt.timedelta(days=older_than)
                sel = []
                for r in runs:
                    p = _Path(r)
                    try:
                        dt = _dt.datetime.strptime(p.name, "%Y%m%d-%H%M%S")
                    except Exception:
                        dt = _dt.datetime.fromtimestamp(p.stat().st_mtime)
                    if dt < cutoff:
                        sel.append(r)
                targets = sel
        else:
            if run:
                targets = [run]
            else:
                # latest
                runs = _fs.list_quarantine_runs()
                if runs:
                    targets = [runs[-1]]
    except Exception:
        targets = []

    if not dry_run and not yes:
        proceed = typer.confirm(
            f"Permanently delete {len(targets) if targets else 'selected'} quarantine run(s)? This cannot be undone.",
            default=False,
        )
        if not proceed:
            console.print("[yellow]Aborted by user[/]")
            return

    res = fs.purge_quarantine(
        run=(run or None), all_runs=all, older_than_days=(older_than or None), dry_run=dry_run
    )
    msg = (
        f"Target runs: {len(res['target_runs'])}\n"
        f"Freed bytes: {res['freed_bytes']:,}\n"
        f"[green]Purge report:[/] {res['purge_report']}"
    )
    if dry_run:
        msg += "\n[yellow]Dry-run: no changes made[/]"
    console.print(msg)
