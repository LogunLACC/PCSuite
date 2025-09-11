import typer
from rich.console import Console
from rich.table import Table
import yaml
from pathlib import Path
import winreg
import datetime
import json
from pcsuite.optimize import network_stack as netopt
from pcsuite.optimize import power as poweropt

app = typer.Typer(help="Optimization profiles (list/apply with dry-run)")
console = Console()

PROFILES_PATH = Path(__file__).parents[1] / "data" / "optimize_profiles.yml"
REPORTS_DIR = Path.cwd() / "reports"


@app.command("list-profiles")
def list_profiles():
    if not PROFILES_PATH.exists():
        console.print("No optimize profiles found")
        return
    data = yaml.safe_load(PROFILES_PATH.read_text(encoding="utf-8")) or {}
    table = Table(title="Optimize Profiles")
    table.add_column("Profile"); table.add_column("Description")
    for name, spec in (data or {}).items():
        table.add_row(str(name), str(spec.get("description", "")))
    console.print(table)


def _reg_set(root_name: str, subkey: str, name: str, typ: str, value):
    if root_name == "HKCU":
        root = winreg.HKEY_CURRENT_USER
    elif root_name == "HKLM":
        root = winreg.HKEY_LOCAL_MACHINE
    else:
        raise ValueError(f"Unsupported root: {root_name}")
    access = winreg.KEY_READ | winreg.KEY_WRITE
    try:
        key = winreg.CreateKeyEx(root, subkey, 0, access)
        with key:
            if typ.upper() == "REG_DWORD":
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
            elif typ.upper() == "REG_SZ":
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
            else:
                raise ValueError(f"Unsupported type: {typ}")
        return True, ""
    except Exception as e:
        return False, str(e)


@app.command()
def apply(
    profile: str,
    dry_run: bool = typer.Option(True, help="Simulate changes"),
    yes: bool = typer.Option(False, help="Skip confirmation for non-dry-run"),
):
    """Apply a named optimization profile from data/optimize_profiles.yml."""
    if not PROFILES_PATH.exists():
        console.print("No optimize profiles found")
        return
    data = yaml.safe_load(PROFILES_PATH.read_text(encoding="utf-8")) or {}
    spec = data.get(profile)
    if not spec:
        console.print(f"[red]Profile not found:[/] {profile}")
        console.print(f"Available: {', '.join(data.keys())}")
        return
    steps = spec.get("steps", [])
    if dry_run:
        console.print(f"[yellow]Dry-run:[/] would apply {len(steps)} steps")
        for s in steps:
            console.print(f"- {s.get('action')}: {s}")
        return
    if not yes:
        if not typer.confirm(f"Apply profile '{profile}' with {len(steps)} steps?", default=False):
            console.print("[yellow]Aborted by user[/]")
            return
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = REPORTS_DIR / f"optimize_apply_{profile}_{ts}.json"
    results = []
    for s in steps:
        action = s.get("action")
        ok = False
        err = ""
        if action == "reg_set":
            root = s.get("root", "HKCU")
            subkey = s.get("key", "")
            name = s.get("name", "")
            typ = s.get("type", "REG_DWORD")
            val = s.get("value", 0)
            ok, err = _reg_set(root, subkey, name, typ, val)
        else:
            err = f"Unsupported action: {action}"
        results.append({"action": action, "ok": ok, "error": err, **s})
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    console.print(f"Applied profile '{profile}'. Report: {report_path}")


@app.command("net")
def optimize_network(
    apply: bool = typer.Option(False, help="Apply recommended TCP settings"),
):
    """Show and optionally apply recommended TCP stack tuning (netsh)."""
    cur = netopt.current_settings()
    recs = netopt.recommend(cur)
    table = Table(title="Network Stack Recommendations")
    table.add_column("Setting"); table.add_column("Current"); table.add_column("Target")
    for r in recs:
        table.add_row(r["key"], r.get("current", ""), r.get("target", ""))
    console.print(table)
    if not apply:
        console.print("[yellow]What-if mode[/]: use --apply to enforce.")
        return
    res = netopt.apply(recs, dry_run=False)
    if res.get("ok"):
        console.print("[green]Applied TCP settings[/]")
    else:
        console.print("[red]Failed to apply some settings[/]")


@app.command("power-plan")
def power_plan(
    profile: str = typer.Option("balanced", help="balanced|high|ultimate|power saver"),
    apply: bool = typer.Option(False, help="Apply selected power plan (default prints what would run)"),
):
    """Switch Windows power plan by name (safe, dry by default)."""
    cur_guid, cur_name = poweropt.current_scheme()
    table = Table(title="Power Plan")
    table.add_column("Current"); table.add_column("GUID")
    table.add_row(cur_name or "?", cur_guid or "?")
    console.print(table)
    res = poweropt.set_scheme_by_name(profile, dry_run=not apply)
    if res.get("ok") and res.get("dry_run"):
        console.print(f"[yellow]Dry-run:[/] {res.get('cmd')}")
    elif res.get("ok"):
        console.print("[green]Power plan switched[/]")
    else:
        console.print(f"[red]Error:[/] {res.get('error','unknown')}")
