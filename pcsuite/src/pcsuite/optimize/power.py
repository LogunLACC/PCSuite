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

    # Canonical scheme names and known default GUIDs (Windows built-ins)
    KNOWN: Dict[str, str] = {
        "balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
        "high performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
        "ultimate performance": "e9a42b02-d5df-448d-aa00-03f14749eb61",
        "power saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
    }

    def canonical(n: str) -> str:
        n = n.strip().lower()
        if n in ("high", "high-performance", "performance", "perf", "hp"):
            return "high performance"
        if n in ("ultimate", "ultimate-performance"):
            return "ultimate performance"
        if n in ("power", "powersaver", "power-saver", "saver"):
            return "power saver"
        if n in ("balanced", "balance", "bal"):
            return "balanced"
        return n

    name_c = canonical(name_l)

    # Map from currently installed schemes
    targets: Dict[str, str | None] = {k: None for k in KNOWN.keys()}
    for guid, n in list_schemes():
        nl = n.strip().lower()
        if nl in targets:
            targets[nl] = guid

    # Prefer installed scheme GUID; else fallback to known default GUID
    guid = targets.get(name_c) or KNOWN.get(name_c)
    if not guid:
        return {"ok": False, "error": f"Scheme '{name}' not found"}

    cmd = f"powercfg -setactive {guid}"
    if dry_run:
        return {"ok": True, "dry_run": True, "cmd": cmd}
    code, out, err = shell.cmdline(cmd)
    return {"ok": code == 0, "dry_run": False, "error": (err or out or "").strip() if code != 0 else ""}
