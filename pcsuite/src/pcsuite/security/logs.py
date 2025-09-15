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

