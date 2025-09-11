import json
import typer
from rich.console import Console
from rich.table import Table
import psutil
from pcsuite.core import shell, elevation
from pcsuite.security import firewall as fw
from pcsuite.security import reputation as rep

app = typer.Typer(help="Security checks and tools")
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


@app.command()
def audit():
    """Audit common security posture settings (read-only)."""
    table = Table(title="Security Audit")
    table.add_column("Check"); table.add_column("Value")

    # Defender service
    try:
        svc = psutil.win_service_get("WinDefend").as_dict()
        table.add_row("Defender (WinDefend)", svc.get("status", "unknown"))
    except Exception:
        table.add_row("Defender (WinDefend)", "not found")

    # Firewall profile states
    code, out, err = shell.cmdline("netsh advfirewall show allprofiles")
    if code == 0 and ("State" in out):
        states = []
        for line in out.splitlines():
            if line.strip().startswith("State"):
                states.append(line.split()[-1])
        table.add_row("Firewall (All Profiles)", ", ".join(states) or "unknown")
    else:
        table.add_row("Firewall", f"error: {err}" if err else "unknown")

    # RDP (fDenyTSConnections = 0 means allowed)
    code, out, err = shell.pwsh("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections")
    if code == 0 and out.strip():
        val = out.strip()
        enabled = (val == "0")
        table.add_row("Remote Desktop", "Enabled" if enabled else "Disabled")
    else:
        table.add_row("Remote Desktop", "unknown")

    # UAC
    code, out, err = shell.pwsh("(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA")
    if code == 0 and out.strip():
        table.add_row("UAC (EnableLUA)", "On" if out.strip() == "1" else "Off")
    else:
        table.add_row("UAC (EnableLUA)", "unknown")

    # SmartScreen (best-effort)
    code, out, err = shell.pwsh("(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled")
    if code == 0 and out.strip():
        table.add_row("SmartScreen", out.strip())
    else:
        table.add_row("SmartScreen", "unknown")

    # Windows Update service
    try:
        wu = psutil.win_service_get("wuauserv").as_dict()
        table.add_row("Windows Update (wuauserv)", wu.get("status", "unknown"))
    except Exception:
        table.add_row("Windows Update (wuauserv)", "not found")

    # BitLocker status (manage-bde)
    code, out, err = shell.cmdline("manage-bde -status")
    if code == 0:
        # naive detection of Protection Status lines
        prot = []
        for line in out.splitlines():
            if "Protection Status" in line:
                prot.append(line.split(":", 1)[1].strip())
        table.add_row("BitLocker", ", ".join(prot) or "unknown")
    else:
        table.add_row("BitLocker", "unknown")

    console.print(table)


@app.command("ports")
def list_ports(limit: int = typer.Option(100, help="Max entries to show")):
    """List listening TCP/UDP ports and owning process (user mode)."""
    table = Table(title="Listening Ports")
    table.add_column("Proto"); table.add_column("Local Address"); table.add_column("PID"); table.add_column("Process")
    seen = 0
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []
    for c in conns:
        try:
            if c.status != psutil.CONN_LISTEN:
                continue
        except Exception:
            # UDP has no status; include UDP where laddr exists and raddr empty
            pass
        proto = "TCP" if c.type == 1 else "UDP"
        if proto == "UDP" and c.raddr:
            continue
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
        pid = str(c.pid or "")
        pname = ""
        if c.pid:
            try:
                pname = psutil.Process(c.pid).name()
            except Exception:
                pname = "?"
        table.add_row(proto, laddr, pid, pname)
        seen += 1
        if seen >= limit:
            break
    console.print(table)


@app.command("defender-scan")
def defender_scan(quick: bool = typer.Option(True, help="Quick scan (default)")):
    """Start a Microsoft Defender scan (quick by default)."""
    mode = "QuickScan" if quick else "FullScan"
    code, out, err = shell.pwsh(f"try {{ Start-MpScan -ScanType {mode}; 'OK' }} catch {{ $_.Exception.Message }}")
    if code == 0 and "OK" in out:
        console.print("[green]Defender scan started[/]")
    else:
        console.print(f"[red]Failed to start scan:[/] {err or out}")


@app.command("firewall")
def firewall(
    enable: bool | None = typer.Option(None, help="Enable or disable all profiles. If omitted, show status."),
    dry_run: bool = typer.Option(True, help="Simulate changes when enabling/disabling"),
):
    """Show or toggle Windows Firewall across profiles (netsh-backed)."""
    if enable is None:
        states = fw.get_profile_states()
        table = Table(title="Firewall Profiles")
        table.add_column("Profile"); table.add_column("State")
        for k in ("Domain", "Private", "Public"):
            table.add_row(k, states.get(k, "unknown"))
        console.print(table)
        return
    res = fw.set_all_profiles(enable=enable, dry_run=dry_run)
    if res.get("ok") and res.get("dry_run"):
        console.print(f"[yellow]Dry-run:[/] {res.get('cmd')}")
    elif res.get("ok"):
        console.print("[green]Firewall updated for all profiles[/]")
    else:
        console.print(f"[red]Failed:[/] {res.get('error','unknown error')}")


@app.command("reputation")
def file_reputation(path: str):
    """Check file reputation indicators (signature and Zone.Identifier)."""
    info = rep.check_reputation(path)
    table = Table(title="File Reputation")
    table.add_column("Field"); table.add_column("Value")
    table.add_row("Path", path)
    table.add_row("Signature", str(info.get("signature")))
    zone = str(info.get("zone_id")) if info.get("has_zone") else "none"
    table.add_row("ZoneId", zone)
    console.print(table)


def _pwsh_json(cmd: str):
    code, out, err = shell.pwsh(f"{cmd} | ConvertTo-Json -Depth 4")
    if code != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


@app.command()
def harden(
    profile: str = typer.Option("baseline", help="Hardening profile: baseline|minimal"),
    apply: bool = typer.Option(False, help="Apply changes (default is what-if)"),
    yes: bool = typer.Option(False, help="Skip confirmation when applying"),
    restart_explorer: bool = typer.Option(
        False, help="Offer to restart Explorer after apply (to apply user UI tweaks)"
    ),
):
    """Baseline hardening checklist with optional apply.

    What-if by default: shows current vs target and whether admin is required.
    Use --apply (and optionally --yes) to make changes.
    """

    def firewall_state():
        code, out, err = shell.cmdline("netsh advfirewall show allprofiles")
        if code == 0:
            states = []
            for line in out.splitlines():
                if line.strip().startswith("State"):
                    states.append(line.split()[-1])
            return ",".join(states) if states else "unknown"
        return "unknown"

    def rdp_enabled():
        code, out, err = shell.pwsh("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections")
        if code == 0 and out.strip():
            return out.strip() == "0"
        return None

    def uac_enabled():
        code, out, err = shell.pwsh("(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA")
        if code == 0 and out.strip():
            return out.strip() == "1"
        return None

    def smartscreen_mode():
        code, out, err = shell.pwsh("(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled")
        if code == 0 and out.strip():
            return out.strip()
        return "unknown"

    def defender_prefs():
        prefs = _pwsh_json("Get-MpPreference | Select-Object DisableRealtimeMonitoring, PUAProtection, EnableNetworkProtection, MAPSReporting, SubmitSamplesConsent")
        if isinstance(prefs, list):
            prefs = prefs[0] if prefs else {}
        return prefs or {}

    def smb1_state():
        info = _pwsh_json("Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object State")
        if isinstance(info, list):
            info = info[0] if info else {}
        return (info or {}).get("State", "unknown")

    actions: list[dict] = []
    profile = (profile or "baseline").lower()
    if profile == "minimal":
        # Non-admin, user-scope tweaks (HKCU)
        def _q_hkcu(path: str, name: str):
            code, out, err = shell.pwsh(
                f"(Get-ItemProperty '{path}' -Name {name} -ErrorAction SilentlyContinue).{name}"
            )
            return out.strip() if code == 0 and out.strip() else "unknown"

        cur_hideext = _q_hkcu("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "HideFileExt")
        cur_hidden = _q_hkcu("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "Hidden")
        cur_autoplay = _q_hkcu("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers", "DisableAutoplay")
        cur_autorun = _q_hkcu("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDriveTypeAutoRun")

        actions = [
            {
                "id": "show_extensions",
                "desc": "Explorer: show file extensions (HideFileExt=0)",
                "current": cur_hideext,
                "target": "0",
                "admin": False,
                "apply": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v HideFileExt /t REG_DWORD /d 0 /f",
            },
            {
                "id": "show_hidden_files",
                "desc": "Explorer: show hidden files (Hidden=1)",
                "current": cur_hidden,
                "target": "1",
                "admin": False,
                "apply": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v Hidden /t REG_DWORD /d 1 /f",
            },
            {
                "id": "disable_autoplay",
                "desc": "Disable AutoPlay for media and devices",
                "current": cur_autoplay,
                "target": "1",
                "admin": False,
                "apply": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\" /v DisableAutoplay /t REG_DWORD /d 1 /f",
            },
            {
                "id": "disable_autorun",
                "desc": "Disable AutoRun (NoDriveTypeAutoRun=255)",
                "current": cur_autorun,
                "target": "255",
                "admin": False,
                "apply": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f",
            },
        ]
    else:
        # Detect current (baseline)
        cur_fw = firewall_state()
        cur_rdp = rdp_enabled()
        cur_uac = uac_enabled()
        cur_ss = smartscreen_mode()
        cur_def = defender_prefs()
        cur_smb1 = smb1_state()

        actions = [
            {
                "id": "firewall_on",
                "desc": "Enable Windows Firewall for all profiles",
                "current": cur_fw,
                "target": "ON,ON,ON",
                "admin": True,
                "apply": "netsh advfirewall set allprofiles state on",
            },
            {
                "id": "rdp_disable",
                "desc": "Disable Remote Desktop",
                "current": "Enabled" if cur_rdp else ("Disabled" if cur_rdp is False else "unknown"),
                "target": "Disabled",
                "admin": True,
                "apply": "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f",
            },
            {
                "id": "uac_enable",
                "desc": "Enable UAC (requires restart)",
                "current": "On" if cur_uac else ("Off" if cur_uac is False else "unknown"),
                "target": "On",
                "admin": True,
                "apply": "reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f",
            },
            {
                "id": "smartscreen_warn",
                "desc": "Enable SmartScreen (Warn)",
                "current": cur_ss,
                "target": "Warn",
                "admin": True,
                "apply": "reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v SmartScreenEnabled /t REG_SZ /d Warn /f",
            },
            {
                "id": "def_realtime",
                "desc": "Defender: enable real-time monitoring",
                "current": "Off" if cur_def.get("DisableRealtimeMonitoring") else "On",
                "target": "On",
                "admin": True,
                "apply": "PowerShell -Command Set-MpPreference -DisableRealtimeMonitoring $false",
            },
            {
                "id": "def_pua",
                "desc": "Defender: enable PUA protection",
                "current": str(cur_def.get("PUAProtection", "unknown")),
                "target": "1",
                "admin": True,
                "apply": "PowerShell -Command Set-MpPreference -PUAProtection 1",
            },
            {
                "id": "def_netprot",
                "desc": "Defender: enable Network Protection",
                "current": str(cur_def.get("EnableNetworkProtection", "unknown")),
                "target": "Enabled",
                "admin": True,
                "apply": "PowerShell -Command Set-MpPreference -EnableNetworkProtection Enabled",
            },
            {
                "id": "smb1_disable",
                "desc": "Disable SMBv1 feature",
                "current": cur_smb1,
                "target": "Disabled",
                "admin": True,
                "apply": "PowerShell -Command Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue",
            },
        ]

    # Present plan
    title = f"Hardening Plan ({profile})"
    table = Table(title=title)
    table.add_column("ID"); table.add_column("Setting"); table.add_column("Current"); table.add_column("Target"); table.add_column("Admin")
    for a in actions:
        table.add_row(a["id"], a["desc"], str(a["current"]), str(a["target"]), "yes" if a["admin"] else "no")
    console.print(table)

    if not apply:
        console.print("[yellow]What-if mode[/]: no changes will be made. Use --apply to enforce.")
        return

    if not yes:
        if not typer.confirm("Apply baseline hardening changes? (may require restart)", default=False):
            console.print("[yellow]Aborted by user[/]")
            return

    # Apply changes
    results = Table(title="Apply Results")
    results.add_column("ID"); results.add_column("Status"); results.add_column("Detail")
    is_admin = elevation.is_admin()
    any_ok = False
    for a in actions:
        if a["admin"] and not is_admin:
            results.add_row(a["id"], "skipped", "requires admin")
            continue
        # Use cmd.exe for reg/netsh or PowerShell passthrough
        cmd = a["apply"]
        if cmd.lower().startswith("powershell"):
            code, out, err = shell.cmdline(cmd)
        else:
            code, out, err = shell.cmdline(cmd)
        if code == 0:
            results.add_row(a["id"], "ok", out.strip()[:200] if out else "")
            any_ok = True
        else:
            results.add_row(a["id"], "error", (err or out or "").strip()[:200])
    console.print(results)
    if profile == "minimal" and any_ok:
        console.print(
            "[yellow]Note[/]: Some Explorer settings may require restarting Explorer or signing out/in to take effect."
        )
        if restart_explorer:
            proceed_restart = True if yes else typer.confirm(
                "Restart Explorer now? This will briefly close the desktop/taskbar.", default=False
            )
            if proceed_restart:
                code, out, err = shell.pwsh(
                    "Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Process explorer.exe; 'OK'"
                )
                if code == 0 and "OK" in (out or ""):
                    console.print("[green]Explorer restarted[/]")
                else:
                    console.print(f"[red]Failed to restart Explorer:[/] {err or out}")
