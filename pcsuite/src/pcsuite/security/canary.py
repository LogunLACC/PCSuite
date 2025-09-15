from __future__ import annotations
import os
import json
import time
import secrets
from pathlib import Path
from typing import List, Dict, Any


def _agent_dir() -> Path:
    root = os.environ.get("ProgramData") or r"C:\\ProgramData"
    base = Path(root) / "PCSuite" / "agent"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _manifest_path() -> Path:
    return _agent_dir() / "canaries.json"


def _load_manifest() -> Dict[str, Any]:
    p = _manifest_path()
    if not p.exists():
        return {"canaries": []}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {"canaries": []}
    except Exception:
        return {"canaries": []}


def _save_manifest(data: Dict[str, Any]) -> None:
    _manifest_path().write_text(json.dumps(data, indent=2), encoding="utf-8")


_BASE_NAMES = [
    "Passwords", "Bank_Statement", "QuickBooks_2024", "Tax_Return",
    "Photos_Backup", "Admin_Creds", "HR_PII", "Invoices_Q1",
    "Payroll", "VPN_Creds",
]
_EXTS = [".txt", ".xlsx", ".pdf", ".zip", ".docx"]


def _rand_name() -> str:
    base = secrets.choice(_BASE_NAMES)
    ext = secrets.choice(_EXTS)
    salt = secrets.token_hex(2)
    return f"{base}_{salt}{ext}"


def generate(dirs: List[str], count_per_dir: int = 1) -> Dict[str, Any]:
    """Create decoy 'canary' files under given directories and record a manifest.

    Returns a summary with created paths.
    """
    manifest = _load_manifest()
    created: List[Dict[str, Any]] = []
    for d in dirs:
        try:
            target_dir = Path(os.path.expandvars(d)).resolve()
            target_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            continue
        for _ in range(max(1, int(count_per_dir))):
            name = _rand_name()
            path = target_dir / name
            token = secrets.token_urlsafe(16)
            content = f"PCSuite Canary – do not modify. Token={token}\n"
            try:
                path.write_text(content, encoding="utf-8")
                ts = time.time()
                try:
                    os.chmod(path, 0o444)  # readonly hint
                except Exception:
                    pass
                stat = path.stat()
                entry = {
                    "path": str(path),
                    "token": token,
                    "created": ts,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                }
                manifest.setdefault("canaries", []).append(entry)
                created.append(entry)
            except Exception:
                continue
    _save_manifest(manifest)
    return {"created": [c["path"] for c in created], "count": len(created)}


def list_canaries() -> Dict[str, Any]:
    m = _load_manifest()
    return {"canaries": m.get("canaries", [])}


def clean() -> Dict[str, Any]:
    m = _load_manifest()
    removed = 0
    for e in list(m.get("canaries", [])):
        p = Path(e.get("path", ""))
        try:
            if p.exists():
                try:
                    os.chmod(p, 0o666)
                except Exception:
                    pass
                p.unlink(missing_ok=True)
            removed += 1
        except Exception:
            continue
    m["canaries"] = []
    _save_manifest(m)
    return {"removed": removed}


def check() -> Dict[str, Any]:
    """Check canaries for tampering: missing or modified size/mtime.

    Returns a dict with 'events' list.
    """
    m = _load_manifest()
    events: List[Dict[str, Any]] = []
    for e in m.get("canaries", []):
        path = Path(e.get("path", ""))
        try:
            if not path.exists():
                events.append({"type": "deleted", "path": str(path)})
                continue
            st = path.stat()
            if int(st.st_size) != int(e.get("size", -1)) or st.st_mtime != e.get("mtime"):
                events.append({"type": "modified", "path": str(path), "size": st.st_size, "mtime": st.st_mtime})
        except Exception:
            continue
    return {"events": events, "count": len(events)}

