from __future__ import annotations
from typing import Dict, Any, List
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


def set_firewall_policy(block_outbound: bool, dry_run: bool = True) -> Dict[str, Any]:
    """Set firewall policy to block or allow outbound for all profiles.

    When block_outbound=True: policy becomes blockinbound,blockoutbound.
    Else: blockinbound,allowoutbound (Windows default).
    """
    pol = "blockinbound,blockoutbound" if block_outbound else "blockinbound,allowoutbound"
    cmd = f"netsh advfirewall set allprofiles firewallpolicy {pol}"
    if dry_run:
        return {"ok": True, "dry_run": True, "cmd": cmd}
    code, out, err = shell.cmdline(cmd)
    return {"ok": code == 0, "dry_run": False, "error": (err or out or "").strip() if code != 0 else ""}


def refresh_isolation_allowlist(ips: List[str], group: str = "PCSuite EDR Isolation", dry_run: bool = True) -> Dict[str, Any]:
    """Recreate outbound allow rules for the given remote IPs under a rule group.

    Deletes existing rules in the group, then adds a rule per IP.
    """
    cmds: List[str] = []
    # Delete existing group rules
    cmds.append(f'netsh advfirewall firewall delete rule group="{group}"')
    # Add allow rules
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        cmds.append(
            f'netsh advfirewall firewall add rule name="{group} Allow {ip}" dir=out action=allow enable=yes remoteip={ip} group="{group}"'
        )
    if dry_run:
        return {"ok": True, "dry_run": True, "cmds": cmds}
    ok = True
    last_err = ""
    for cmd in cmds:
        code, out, err = shell.cmdline(cmd)
        if code != 0:
            ok = False
            last_err = (err or out or "")
    return {"ok": ok, "dry_run": False, "error": last_err}
