
from dataclasses import dataclass
from pathlib import Path
import os
import yaml
import glob
import datetime
import json
import shutil
import stat
import ctypes
from ctypes import wintypes
from . import elevation

DATA_DIR = Path(__file__).parent.parent / "data"
SIGNATURES_PATH = DATA_DIR / "signatures.yml"
EXCLUSIONS_PATH = DATA_DIR / "exclusions.yml"
REPORTS_DIR = Path.cwd() / "reports"
QUARANTINE_DIR = REPORTS_DIR / "quarantine"

@dataclass
class Target:
    path: str
    size: int

def _load_yaml(path):
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def _expand_env_glob(pattern):
    # Expand environment variables and glob
    expanded = os.path.expandvars(pattern)
    return glob.glob(expanded, recursive=True)

def _is_excluded(path, exclusions):
    # Simple exclusion check (can be improved)
    for ex in exclusions:
        if Path(path).match(ex):
            return True
    return False


def _norm(p: str | os.PathLike) -> Path:
    try:
        return Path(p).resolve()
    except Exception:
        return Path(p)


def _user_roots() -> list[Path]:
    roots: list[Path] = []
    for env in ("USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"):
        val = os.environ.get(env)
        if not val:
            continue
        try:
            roots.append(_norm(val))
        except Exception:
            continue
    # De-duplicate
    uniq: list[Path] = []
    seen: set[str] = set()
    for r in roots:
        s = str(r).lower()
        if s not in seen:
            uniq.append(r)
            seen.add(s)
    return uniq


def _is_under_any(path: str, roots: list[Path]) -> bool:
    p = _norm(path)
    for root in roots:
        try:
            p.relative_to(root)
            return True
        except Exception:
            continue
    return False

def enumerate_targets(categories, scope: str = "auto"):
    sigs = _load_yaml(SIGNATURES_PATH)
    excls = _load_yaml(EXCLUSIONS_PATH)
    exclusions = excls.get("paths", []) if isinstance(excls, dict) else []
    targets = []
    if not sigs or "categories" not in sigs:
        return []
    # Resolve scope
    sc = (scope or "auto").lower()
    if sc not in {"auto", "user", "all"}:
        sc = "auto"
    if sc == "auto":
        sc = "all" if elevation.is_admin() else "user"
    user_only = sc == "user"
    allowed_roots = _user_roots() if user_only else []
    for cat in categories:
        cat = cat.strip()
        catdef = sigs["categories"].get(cat)
        if not catdef:
            continue
        globs = catdef.get("globs", [])
        for pattern in globs:
            for fpath in _expand_env_glob(pattern):
                if not os.path.isfile(fpath):
                    continue
                if _is_excluded(fpath, exclusions):
                    continue
                if user_only and not _is_under_any(fpath, allowed_roots):
                    # Skip files outside of user-writable roots in non-admin mode
                    continue
                try:
                    size = os.path.getsize(fpath)
                except Exception:
                    size = 0
                targets.append(Target(path=fpath, size=size))
    return targets

def write_audit_report(targets, action="preview"):
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = REPORTS_DIR / f"{action}_{ts}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump([t.__dict__ for t in targets], f, indent=2)
    return str(report_path)


def list_quarantine_runs() -> list[str]:
    """Return sorted list of quarantine run directories as strings."""
    QUARANTINE_DIR.mkdir(exist_ok=True)
    runs = [p for p in QUARANTINE_DIR.iterdir() if p.is_dir()]
    runs.sort()
    return [str(p) for p in runs]


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for p in path.rglob("*"):
            try:
                if p.is_file():
                    total += p.stat().st_size
            except Exception:
                continue
    except Exception:
        return 0
    return total


def purge_quarantine(
    run: str | None = None,
    all_runs: bool = False,
    older_than_days: int | None = None,
    dry_run: bool = False,
):
    """Permanently delete files in quarantine.

    - If `all_runs` is True, purges all runs.
    - Else if `older_than_days` is set, purges runs older than N days.
    - Else if `run` is provided, purges that run directory or 'latest'.
    - Else, purges the latest run.
    Returns summary dict with counts and report path.
    """
    REPORTS_DIR.mkdir(exist_ok=True)
    QUARANTINE_DIR.mkdir(exist_ok=True)
    candidates: list[Path] = []
    runs = [p for p in QUARANTINE_DIR.iterdir() if p.is_dir()]
    runs.sort()
    now = datetime.datetime.now()
    if all_runs:
        candidates = runs
    elif older_than_days is not None and older_than_days > 0:
        cutoff = now - datetime.timedelta(days=older_than_days)
        for r in runs:
            try:
                # parse timestamp folder name if follows YYYYMMDD-HHMMSS, else fallback to mtime
                dt = datetime.datetime.strptime(r.name, "%Y%m%d-%H%M%S")
            except Exception:
                dt = datetime.datetime.fromtimestamp(r.stat().st_mtime)
            if dt < cutoff:
                candidates.append(r)
    else:
        if run:
            if run.lower() == "latest":
                if runs:
                    candidates = [runs[-1]]
            else:
                rr = Path(run)
                if not rr.is_absolute():
                    rr = QUARANTINE_DIR / run
                if rr.exists() and rr.is_dir():
                    candidates = [rr]
        else:
            if runs:
                candidates = [runs[-1]]

    deleted_runs = 0
    freed_bytes = 0
    errors: list[dict] = []
    for r in candidates:
        size = _dir_size(r)
        if dry_run:
            freed_bytes += size
            continue
        try:
            shutil.rmtree(r, ignore_errors=False)
            deleted_runs += 1
            freed_bytes += size
        except Exception as ex:
            errors.append({"run": str(r), "error": str(ex)})

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = REPORTS_DIR / f"purge_{ts}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "target_runs": [str(p) for p in candidates],
                "deleted_runs": deleted_runs if not dry_run else 0,
                "freed_bytes": freed_bytes,
                "errors": errors,
                "dry_run": dry_run,
            },
            f,
            indent=2,
        )
    return {
        "target_runs": [str(p) for p in candidates],
        "deleted_runs": deleted_runs,
        "freed_bytes": freed_bytes,
        "purge_report": str(report_path),
        "dry_run": dry_run,
    }

def _send_to_recycle(path: str) -> bool:
    try:
        # Lazy import to keep dependency optional at import time
        from send2trash import send2trash  # type: ignore

        send2trash(path)
        return True
    except Exception:
        return False


def _delete_on_reboot(path: str) -> bool:
    try:
        # BOOL MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags)
        # Passing None for new filename and MOVEFILE_DELAY_UNTIL_REBOOT schedules delete.
        MoveFileExW = ctypes.windll.kernel32.MoveFileExW
        MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        MoveFileExW.restype = wintypes.BOOL
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
        res = MoveFileExW(path, None, MOVEFILE_DELAY_UNTIL_REBOOT)
        return bool(res)
    except Exception:
        return False


def execute_cleanup(
    categories,
    dry_run: bool = False,
    scope: str = "auto",
    delete_mode: str = "quarantine",  # quarantine|recycle|delete
    on_reboot_fallback: bool = False,
):
    # Move files to a timestamped quarantine directory and record rollback metadata
    sigs = _load_yaml(SIGNATURES_PATH)
    excls = _load_yaml(EXCLUSIONS_PATH)
    exclusions = excls.get("paths", []) if isinstance(excls, dict) else []
    REPORTS_DIR.mkdir(exist_ok=True)
    if not dry_run:
        QUARANTINE_DIR.mkdir(exist_ok=True)
    # Enumerate (respect scope)
    targets = enumerate_targets(categories, scope=scope)
    if not targets:
        return {
            "moved": 0,
            "failed": 0,
            "cleanup_report": None,
            "rollback_file": None,
            "dry_run": dry_run,
        }
    # Timestamped run dir (only for quarantine)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = QUARANTINE_DIR / ts
    if delete_mode == "quarantine" and not dry_run:
        run_dir.mkdir(parents=True, exist_ok=True)

    results = []
    rollback_entries = []
    idx = 0
    for t in targets:
        src = t.path
        # Ensure path is a file and still exists
        if not os.path.isfile(src):
            results.append({"src": src, "dst": None, "size": t.size, "ok": False, "error": "not a file"})
            continue
        # Destination in quarantine
        idx += 1
        dst = str(run_dir / f"{idx:06d}_{os.path.basename(src)}") if delete_mode == "quarantine" else None
        ok = False
        err = None
        if dry_run:
            ok = True
        else:
            try:
                # Make file writable in case of read-only attribute
                try:
                    os.chmod(src, stat.S_IWRITE)
                except Exception:
                    pass
                if delete_mode == "quarantine":
                    # Move into quarantine
                    assert dst is not None
                    shutil.move(src, dst)
                    ok = True
                elif delete_mode == "recycle":
                    ok = _send_to_recycle(src)
                    if not ok and on_reboot_fallback:
                        ok = _delete_on_reboot(src)
                elif delete_mode == "delete":
                    try:
                        os.remove(src)
                        ok = True
                    except Exception:
                        if on_reboot_fallback:
                            ok = _delete_on_reboot(src)
                        else:
                            raise
                else:
                    err = f"invalid delete_mode: {delete_mode}"
            except Exception as e:
                err = str(e)
        results.append({
            "src": src,
            "dst": dst if (ok and dst) else None,
            "size": t.size,
            "ok": ok,
            "error": err,
            "mode": delete_mode,
        })
        if ok and not dry_run and delete_mode == "quarantine":
            rollback_entries.append({"src": src, "dst": dst, "size": t.size})

    # Write cleanup audit and rollback files
    # Preserve legacy naming for quarantine to keep tests stable
    if delete_mode == "quarantine":
        action = "cleanup_dryrun" if dry_run else "cleanup"
    else:
        action = (f"cleanup_{delete_mode}_dryrun" if dry_run else f"cleanup_{delete_mode}")
    cleanup_report = REPORTS_DIR / f"{action}_{ts}.json"
    with open(cleanup_report, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    rollback_file = None
    if not dry_run and delete_mode == "quarantine":
        rollback_file = REPORTS_DIR / f"rollback_{ts}.json"
        with open(rollback_file, "w", encoding="utf-8") as f:
            json.dump(rollback_entries, f, indent=2)

    return {
        "moved": sum(1 for r in results if r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok")),
        "cleanup_report": str(cleanup_report),
        "rollback_file": str(rollback_file) if rollback_file else None,
        "dry_run": dry_run,
        "mode": delete_mode,
    }

def find_latest_rollback():
    REPORTS_DIR.mkdir(exist_ok=True)
    files = sorted(REPORTS_DIR.glob("rollback_*.json"))
    return str(files[-1]) if files else ""

def execute_rollback(rollback_path: str | None = None, dry_run: bool = False):
    # Restore files from quarantine using a rollback mapping file
    if not rollback_path:
        rollback_path = find_latest_rollback()
    if not rollback_path:
        return {"restored": 0, "failed": 0, "restore_report": None, "dry_run": dry_run}
    try:
        with open(rollback_path, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except Exception:
        entries = []
    results = []
    for e in entries:
        src = e.get("src")  # original location
        dst = e.get("dst")  # quarantine file
        ok = False
        err = None
        if dry_run:
            # Assume would restore if mapping exists
            ok = True
        else:
            try:
                if not dst or not os.path.isfile(dst):
                    raise FileNotFoundError("quarantined file not found")
                Path(src).parent.mkdir(parents=True, exist_ok=True)
                # If destination exists already, replace it
                if os.path.exists(src):
                    # Move existing to a side name to prevent overwrite loss
                    side = src + ".pcsuite.bak"
                    try:
                        shutil.move(src, side)
                    except Exception:
                        pass
                shutil.move(dst, src)
                ok = True
            except Exception as ex:
                err = str(ex)
        results.append({"src": src, "from": dst, "ok": ok, "error": err})

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    action = "restore_dryrun" if dry_run else "restore"
    restore_report = REPORTS_DIR / f"{action}_{ts}.json"
    with open(restore_report, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return {
        "restored": sum(1 for r in results if r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok")),
        "restore_report": str(restore_report),
        "dry_run": dry_run,
    }
