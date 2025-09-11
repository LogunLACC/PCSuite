from __future__ import annotations
from typing import Dict, Any
from pcsuite.core import shell


def quick_scan() -> Dict[str, Any]:
    """Start a Microsoft Defender quick scan. Returns a status dict.

    Uses PowerShell Start-MpScan. If Defender is unavailable, returns an error.
    """
    code, out, err = shell.pwsh("try { Start-MpScan -ScanType QuickScan; 'OK' } catch { $_.Exception.Message }")
    ok = code == 0 and (out or "").find("OK") >= 0
    return {"ok": ok, "error": None if ok else (err or out or "").strip()}


def preferences() -> Dict[str, Any]:
    """Return Defender preferences via Get-MpPreference (best-effort)."""
    code, out, err = shell.pwsh("try { Get-MpPreference | ConvertTo-Json -Depth 3 } catch { '' }")
    if code != 0 or not (out or "").strip():
        return {}
    try:
        import json

        data = json.loads(out)
        if isinstance(data, list):
            data = data[0] if data else {}
        return data or {}
    except Exception:
        return {}
