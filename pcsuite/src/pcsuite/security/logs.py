from __future__ import annotations
from typing import List, Dict, Any
import os
from pcsuite.core import shell


def _pwsh_json(cmd: str) -> Any:
    code, out, err = shell.pwsh(f"{cmd} | ConvertTo-Json -Depth 5")
    if code != 0 or not (out or "").strip():
        return None
    try:
        import json

        return json.loads(out)
    except Exception:
        return None


def get_security_events(limit: int = 200) -> List[Dict[str, Any]]:
    """Return latest Security events (best-effort). Non-Windows returns empty list."""
    if os.name != "nt":
        return []
    data = _pwsh_json(f"Get-WinEvent -LogName Security -MaxEvents {int(limit)}")
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    # Normalize: keep a subset of properties we often need
    events: List[Dict[str, Any]] = []
    for ev in data:
        try:
            props = ev.get("Properties") or []
            msg = ev.get("Message", "")
            events.append({
                "RecordId": ev.get("RecordId"),
                "Id": ev.get("Id"),
                "ProviderName": ev.get("ProviderName"),
                "LevelDisplayName": ev.get("LevelDisplayName"),
                "TimeCreated": ev.get("TimeCreated"),
                "Message": msg,
                "Properties": props,
            })
        except Exception:
            continue
    return events


def get_powershell_events(limit: int = 200) -> List[Dict[str, Any]]:
    if os.name != "nt":
        return []
    log = 'Microsoft-Windows-PowerShell/Operational'
    data = _pwsh_json(f"Get-WinEvent -LogName '{log}' -MaxEvents {int(limit)}")
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    events: List[Dict[str, Any]] = []
    for ev in data:
        try:
            msg = ev.get("Message", "")
            events.append({
                "RecordId": ev.get("RecordId"),
                "Id": ev.get("Id"),
                "ProviderName": ev.get("ProviderName"),
                "LevelDisplayName": ev.get("LevelDisplayName"),
                "TimeCreated": ev.get("TimeCreated"),
                "Message": msg,
            })
        except Exception:
            continue
    return events


def delta_security_events(last_id: int = 0, limit: int = 200) -> tuple[list[Dict[str, Any]], int]:
    evs = get_security_events(limit=limit)
    new = [e for e in evs if (e.get("RecordId") or 0) > (last_id or 0)]
    latest = max((e.get("RecordId") or 0) for e in evs) if evs else last_id
    return new, (latest or last_id)


def delta_powershell_events(last_id: int = 0, limit: int = 200) -> tuple[list[Dict[str, Any]], int]:
    evs = get_powershell_events(limit=limit)
    new = [e for e in evs if (e.get("RecordId") or 0) > (last_id or 0)]
    latest = max((e.get("RecordId") or 0) for e in evs) if evs else last_id
    return new, (latest or last_id)
