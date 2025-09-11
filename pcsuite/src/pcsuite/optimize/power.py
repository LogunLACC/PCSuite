from __future__ import annotations
from typing import Dict, Any, List, Tuple
import re
from pcsuite.core import shell


def current_scheme() -> Tuple[str | None, str | None]:
    code, out, err = shell.cmdline("powercfg /GETACTIVESCHEME")
    if code != 0:
        return None, None
    # Output: Power Scheme GUID: xxxxxxxx-...  (Balanced)
    m = re.search(r"Power Scheme GUID:\s+([0-9a-fA-F\-]+)\s+\(([^)]+)\)", out or "")
    if not m:
        return None, None
    return m.group(1), m.group(2)


def list_schemes() -> List[Tuple[str, str]]:
    code, out, err = shell.cmdline("powercfg -l")
    if code != 0:
        return []
    results: List[Tuple[str, str]] = []
    for line in (out or "").splitlines():
        m = re.search(r"([0-9a-fA-F\-]{36})\s+\(([^)]+)\)", line)
        if m:
            results.append((m.group(1), m.group(2)))
    return results


def set_scheme_by_name(name: str, dry_run: bool = True) -> Dict[str, Any]:
    name_l = name.strip().lower()
    targets = {"balanced": None, "high performance": None, "ultimate performance": None, "power saver": None}
    for guid, n in list_schemes():
        nl = n.strip().lower()
        for k in list(targets.keys()):
            if nl == k:
                targets[k] = guid
    # Alias
    if name_l in ("high", "high-performance"):
        name_l = "high performance"
    if name_l in ("ultimate", "ultimate-performance"):
        name_l = "ultimate performance"
    if name_l not in targets or not targets[name_l]:
        return {"ok": False, "error": f"Scheme '{name}' not found"}
    cmd = f"powercfg -setactive {targets[name_l]}"
    if dry_run:
        return {"ok": True, "dry_run": True, "cmd": cmd}
    code, out, err = shell.cmdline(cmd)
    return {"ok": code == 0, "dry_run": False, "error": (err or out or "").strip() if code != 0 else ""}
