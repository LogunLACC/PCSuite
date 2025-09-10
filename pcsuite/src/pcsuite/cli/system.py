import json
import platform
import datetime
import psutil
import typer
from rich.console import Console
from rich.table import Table
from pcsuite.core import shell


app = typer.Typer(help="System information: OS, CPU, RAM, BIOS, uptime")
console = Console()


def _pwsh_json(cmd: str) -> dict | list | None:
    code, out, err = shell.pwsh(f"{cmd} | ConvertTo-Json -Depth 4")
    if code != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


@app.command()
def info():
    """Show key system details (no admin required)."""
    # OS
    os_info = _pwsh_json(
        "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime"
    )
    cs_info = _pwsh_json(
        "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Domain,Username"
    )
    bios_info = _pwsh_json(
        "Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion,Manufacturer,ReleaseDate,SerialNumber"
    )
    cpu_name = None
    cpu_info = _pwsh_json(
        "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed"
    )

    # Normalize potential list results into dict (take first)
    def first(obj):
        if isinstance(obj, list):
            return obj[0] if obj else None
        return obj

    osd = first(os_info) or {}
    csd = first(cs_info) or {}
    biosd = first(bios_info) or {}
    cpid = first(cpu_info) or {}

    boot_ts = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_ts

    vm = psutil.virtual_memory()
    total_ram = vm.total
    avail_ram = vm.available

    # Compose table
    t = Table(title="System Information")
    t.add_column("Property")
    t.add_column("Value")

    # General
    t.add_row("Computer", f"{csd.get('Manufacturer','?')} {csd.get('Model','?')}")
    t.add_row("Domain/User", f"{csd.get('Domain','?')} / {csd.get('Username','?')}")
    t.add_row(
        "OS",
        f"{osd.get('Caption', platform.platform())} {osd.get('Version','')} (Build {osd.get('BuildNumber','?')}) {osd.get('OSArchitecture','')}",
    )
    t.add_row("Boot Time", boot_ts.strftime("%Y-%m-%d %H:%M:%S"))
    t.add_row("Uptime", str(uptime).split(".")[0])

    # CPU
    t.add_row(
        "CPU",
        cpid.get("Name")
        or platform.processor()
        or platform.machine(),
    )
    t.add_row(
        "Cores/Logical",
        f"{psutil.cpu_count(logical=False) or '?'} / {psutil.cpu_count() or '?'}",
    )
    try:
        freq = psutil.cpu_freq()
        if freq and freq.max:
            t.add_row("Max Clock", f"{freq.max/1000:.2f} GHz")
    except Exception:
        pass

    # Memory
    t.add_row("RAM Total", f"{total_ram/ (1024**3):.2f} GiB")
    t.add_row("RAM Available", f"{avail_ram/ (1024**3):.2f} GiB")

    # BIOS
    bios_ver = biosd.get("SMBIOSBIOSVersion") or biosd.get("Version") or "?"
    bios_mfr = biosd.get("Manufacturer", "?")
    bios_date = biosd.get("ReleaseDate", "?")
    t.add_row("BIOS", f"{bios_mfr} {bios_ver}")
    t.add_row("BIOS Release", str(bios_date))

    # Secure Boot (best-effort)
    sec = _pwsh_json(
        "try { [pscustomobject]@{ SecureBoot = (Confirm-SecureBootUEFI) } } catch { [pscustomobject]@{ SecureBoot = 'n/a' } }"
    )
    secd = first(sec) or {}
    if secd:
        t.add_row("Secure Boot", str(secd.get("SecureBoot", "n/a")))

    console.print(t)


def _bytes_to_gib(n: int | float | None) -> str:
    try:
        return f"{(float(n) / (1024**3)):.2f} GiB"
    except Exception:
        return "?"


@app.command()
def drives():
    """Show logical volumes and physical disks with health/SMART (best-effort)."""
    # Logical volumes via Win32_LogicalDisk for label/fs/size/free
    vols = _pwsh_json(
        "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType"
    )
    if isinstance(vols, dict):
        vols = [vols]
    vt = Table(title="Volumes")
    vt.add_column("Drive"); vt.add_column("Label"); vt.add_column("FS"); vt.add_column("Size"); vt.add_column("Free"); vt.add_column("Used%")
    if isinstance(vols, list):
        for v in vols:
            try:
                # 3 = Local Disk
                if v.get("DriveType") not in (2, 3):
                    # include removable (2) and local fixed (3)
                    continue
            except Exception:
                pass
            size = float(v.get("Size") or 0)
            free = float(v.get("FreeSpace") or 0)
            used_pct = f"{((size-free)/size*100):.0f}%" if size > 0 else "?"
            vt.add_row(
                str(v.get("DeviceID", "")),
                str(v.get("VolumeName", "")) or "",
                str(v.get("FileSystem", "")) or "",
                _bytes_to_gib(size),
                _bytes_to_gib(free),
                used_pct,
            )
    console.print(vt)

    # Physical disks via Get-PhysicalDisk (health) and Win32_DiskDrive (model/serial)
    pds = _pwsh_json(
        "Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,HealthStatus,OperationalStatus,Size"
    ) or []
    if isinstance(pds, dict):
        pds = [pds]
    wdd = _pwsh_json(
        "Get-CimInstance Win32_DiskDrive | Select-Object Index,Model,SerialNumber,Status,Size,InterfaceType,PNPDeviceID,DeviceID"
    ) or []
    if isinstance(wdd, dict):
        wdd = [wdd]
    smart = _pwsh_json(
        "Get-WmiObject -Namespace root\\wmi -Class MSStorageDriver_FailurePredictStatus | Select-Object InstanceName,PredictFailure"
    ) or []
    if isinstance(smart, dict):
        smart = [smart]

    # Build SMART hints keyed by model/serial appearance in InstanceName
    smart_hints: dict[str, str] = {}
    for s in smart:
        inst = str(s.get("InstanceName", ""))
        pf = str(s.get("PredictFailure", "")).lower() in ("true", "1")
        norm_inst = inst.lower().replace(" ", "").replace("_", "").replace("-", "")
        smart_hints[norm_inst] = "Pred Fail" if pf else "OK"

    def guess_smart(model: str | None, serial: str | None) -> str:
        cand = []
        if model:
            cand.append(str(model))
        if serial:
            cand.append(str(serial))
        for c in cand:
            n = c.lower().replace(" ", "").replace("_", "").replace("-", "")
            for inst, status in smart_hints.items():
                if n and n in inst:
                    return status
        return "unknown"

    dt = Table(title="Physical Disks")
    dt.add_column("Model"); dt.add_column("Serial"); dt.add_column("Media"); dt.add_column("Size"); dt.add_column("Health"); dt.add_column("SMART")
    if pds:
        for d in pds:
            model = d.get("FriendlyName", "")
            serial = d.get("SerialNumber", "")
            media = d.get("MediaType", "")
            size = d.get("Size", 0)
            health = d.get("HealthStatus", "")
            dt.add_row(
                str(model),
                str(serial) or "",
                str(media) or "",
                _bytes_to_gib(size),
                str(health) or "",
                guess_smart(model, serial),
            )
    else:
        # Fallback to Win32_DiskDrive only
        for d in wdd:
            model = d.get("Model", "")
            serial = d.get("SerialNumber", "")
            size = d.get("Size", 0)
            status = d.get("Status", "")
            dt.add_row(str(model), str(serial) or "", "", _bytes_to_gib(size), str(status) or "", guess_smart(model, serial))

    console.print(dt)
