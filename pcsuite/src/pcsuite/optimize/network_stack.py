from __future__ import annotations
from typing import Dict, Any, List
from pcsuite.core import shell


def current_settings() -> Dict[str, str]:
    code, out, err = shell.cmdline("netsh int tcp show global")
    if code != 0:
        return {}
    settings: Dict[str, str] = {}
    for raw in (out or "").splitlines():
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        settings[k.strip()] = v.strip()
    return settings


def recommend(settings: Dict[str, str] | None = None) -> List[Dict[str, str]]:
    """Return a list of recommended changes based on current settings.

    Conservative defaults aimed at Windows 10/11 general desktops.
    """
    s = settings or current_settings() or {}
    recs: List[Dict[str, str]] = []
    def want(key: str, value: str, param: str):
        cur = s.get(key)
        if cur is None:
            return
        if cur.lower() != value.lower():
            recs.append({"key": key, "current": cur, "target": value, "param": param})

    want("Receive Window Auto-Tuning Level", "normal", "autotuninglevel=normal")
    # Enable ECN for modern networks (safe on most)
    want("ECN Capability", "enabled", "ecncapability=enabled")
    # Modern congestion provider: CTCP is default on newer builds; set explicitly
    want("Add-On Congestion Control Provider", "ctcp", "congestionprovider=ctcp")
    # Ensure RSS is enabled (multi-core NICs)
    want("Receive-Side Scaling State", "enabled", "rss=enabled")
    return recs


def apply(recs: List[Dict[str, str]], dry_run: bool = True) -> Dict[str, Any]:
    cmds = [f"netsh int tcp set global {r['param']}" for r in recs]
    if dry_run:
        return {"ok": True, "dry_run": True, "cmds": cmds}
    any_err = False
    for cmd in cmds:
        code, out, err = shell.cmdline(cmd)
        if code != 0:
            any_err = True
    return {"ok": not any_err, "dry_run": False}
