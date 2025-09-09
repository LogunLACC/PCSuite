from __future__ import annotations
import os
import json
import datetime
from pathlib import Path
import winreg
from typing import List, Dict
from .fs import REPORTS_DIR
from .shell import cmdline


REGISTRY_CLEAN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
]


def _split_root(path: str):
    path = path.strip()
    if path.startswith("HKCU\\"):
        return winreg.HKEY_CURRENT_USER, path[5:]
    if path.startswith("HKLM\\"):
        return winreg.HKEY_LOCAL_MACHINE, path[5:]
    raise ValueError(f"Unsupported root in path: {path}")


def _enum_values(key) -> List[str]:
    vals = []
    i = 0
    while True:
        try:
            name, _, _ = winreg.EnumValue(key, i)
            vals.append(name)
            i += 1
        except OSError:
            break
    return vals


def _enum_subkeys(key) -> List[str]:
    subs = []
    i = 0
    while True:
        try:
            name = winreg.EnumKey(key, i)
            subs.append(name)
            i += 1
        except OSError:
            break
    return subs


def _delete_tree(root, subkey):
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            for child in _enum_subkeys(k):
                _delete_tree(root, subkey + "\\" + child)
    except OSError:
        pass
    try:
        winreg.DeleteKey(root, subkey)
        return True
    except OSError:
        return False


def _export_key(full_path: str, out_file: Path) -> bool:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    code, out, err = cmdline(f'reg export "{full_path}" "{out_file}" /y')
    return code == 0


def registry_preview() -> Dict:
    preview = []
    for full in REGISTRY_CLEAN_KEYS:
        try:
            root, sub = _split_root(full)
            with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
                vals = [v for v in _enum_values(k) if v]
                subs = _enum_subkeys(k)
            preview.append({"key": full, "values": vals, "subkeys": subs})
        except OSError:
            preview.append({"key": full, "values": [], "subkeys": []})
    return {"targets": preview}


def registry_cleanup(dry_run: bool = False) -> Dict:
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = REPORTS_DIR / "registry" / "backups" / ts
    actions = []
    for full in REGISTRY_CLEAN_KEYS:
        root, sub = _split_root(full)
        # Export key backup (if exists)
        exported = False
        try:
            with winreg.OpenKey(root, sub, 0, winreg.KEY_READ):
                exported = _export_key(full, backup_dir / (sub.replace("\\", "_") + ".reg"))
        except OSError:
            exported = False
        # Delete values/subkeys
        removed_values = 0
        removed_subkeys = 0
        if not dry_run:
            try:
                with winreg.OpenKey(root, sub, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
                    for v in _enum_values(k):
                        if v == "(Default)":
                            continue
                        try:
                            winreg.DeleteValue(k, v)
                            removed_values += 1
                        except OSError:
                            pass
            except OSError:
                pass
            # Remove subkeys under the key (for MRU listings like RecentDocs)
            for _ in range(2):  # try twice in case of nested trees
                try:
                    with winreg.OpenKey(root, sub, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
                        for child in _enum_subkeys(k):
                            if _delete_tree(root, sub + "\\" + child):
                                removed_subkeys += 1
                except OSError:
                    break
        actions.append({
            "key": full,
            "backup": str(backup_dir) if exported else "",
            "removed_values": removed_values,
            "removed_subkeys": removed_subkeys,
        })

    # Write reports
    cleanup_report = REPORTS_DIR / f"registry_cleanup_{ts}.json"
    with open(cleanup_report, "w", encoding="utf-8") as f:
        json.dump(actions, f, indent=2)
    rollback_manifest = REPORTS_DIR / f"registry_rollback_{ts}.json"
    with open(rollback_manifest, "w", encoding="utf-8") as f:
        json.dump({"backup_dir": str(backup_dir)}, f, indent=2)
    return {"cleanup_report": str(cleanup_report), "rollback_file": str(rollback_manifest), "dry_run": dry_run}


def registry_rollback(manifest_path: str | None = None, dry_run: bool = False) -> Dict:
    files = sorted(REPORTS_DIR.glob("registry_rollback_*.json"))
    if not manifest_path:
        manifest_path = str(files[-1]) if files else ""
    if not manifest_path:
        return {"restored": 0, "restore_report": None, "dry_run": dry_run}
    try:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        backup_dir = Path(data.get("backup_dir", ""))
    except Exception:
        backup_dir = Path()
    if not backup_dir.exists():
        return {"restored": 0, "restore_report": None, "dry_run": dry_run}
    restored = 0
    errs: list[dict] = []
    if not dry_run:
        for reg_file in backup_dir.glob("*.reg"):
            code, out, err = cmdline(f'reg import "{reg_file}"')
            if code == 0:
                restored += 1
            else:
                errs.append({"file": str(reg_file), "error": err})
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    restore_report = REPORTS_DIR / f"registry_restore_{ts}.json"
    with open(restore_report, "w", encoding="utf-8") as f:
        json.dump({"restored": restored, "errors": errs}, f, indent=2)
    return {"restored": restored, "restore_report": str(restore_report), "dry_run": dry_run}
