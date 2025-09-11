from __future__ import annotations
from typing import Dict, Any
from pcsuite.core import shell


def _parse_allprofiles(output: str) -> Dict[str, str]:
    states: Dict[str, str] = {"Domain": "unknown", "Private": "unknown", "Public": "unknown"}
    current = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("domain profile"):
            current = "Domain"
        elif line.lower().startswith("private profile"):
            current = "Private"
        elif line.lower().startswith("public profile"):
            current = "Public"
        elif line.startswith("State") and current:
            # Example: State                                 ON
            parts = line.split()
            if parts:
                states[current] = parts[-1].upper()
    return states


def get_profile_states() -> Dict[str, str]:
    """Return firewall states for Domain/Private/Public via netsh (ON/OFF/unknown)."""
    code, out, err = shell.cmdline("netsh advfirewall show allprofiles")
    if code != 0:
        return {"Domain": "unknown", "Private": "unknown", "Public": "unknown"}
    return _parse_allprofiles(out)


def set_all_profiles(enable: bool, dry_run: bool = True) -> Dict[str, Any]:
    """Enable or disable firewall across all profiles. Default dry-run."""
    cmd = f"netsh advfirewall set allprofiles state {'on' if enable else 'off'}"
    if dry_run:
        return {"ok": True, "dry_run": True, "cmd": cmd}
    code, out, err = shell.cmdline(cmd)
    return {"ok": code == 0, "dry_run": False, "error": (err or out or "").strip() if code != 0 else ""}
