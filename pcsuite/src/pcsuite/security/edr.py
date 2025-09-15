from __future__ import annotations
from typing import Dict, Any, List
import platform
import psutil

from pcsuite.security import firewall as fw
from pcsuite.security import reputation as rep
from pcsuite.security import defender as defn
from pcsuite.security import logs as seclogs
from pcsuite.security import rules as secrules
from pcsuite.core import fs as corefs


def status() -> Dict[str, Any]:
    states = fw.get_profile_states()
    enrolled = False  # Placeholder for future enrollment
    return {
        "product": "PCSuite EDR (prototype)",
        "version": "0.1",
        "os": platform.platform(),
        "enrolled": enrolled,
        "firewall": states,
    }


def isolate(enable: bool, dry_run: bool = True) -> Dict[str, Any]:
    """High-level isolation toggle via firewall profiles.

    For now, map to fw.set_all_profiles(on/off) with dry-run default.
    In a future iteration, tighten outbound policy selectively.
    """
    res = fw.set_all_profiles(enable=enable, dry_run=dry_run)
    return {"ok": res.get("ok", False), "dry_run": res.get("dry_run", dry_run), "detail": res}


def list_listening_ports(limit: int = 100) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []
    for c in conns:
        try:
            proto = "TCP" if c.type == 1 else "UDP"
            if proto == "TCP" and c.status != psutil.CONN_LISTEN:
                continue
            if proto == "UDP" and c.raddr:
                continue
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except Exception:
                    pname = "?"
            out.append({"proto": proto, "laddr": laddr, "pid": c.pid or 0, "proc": pname})
            if len(out) >= limit:
                break
        except Exception:
            continue
    return out


def quick_triage_summary() -> Dict[str, Any]:
    try:
        procs = len(psutil.pids())
    except Exception:
        procs = 0
    try:
        ports = len(list_listening_ports(limit=1000))
    except Exception:
        ports = 0
    return {
        "process_count": procs,
        "listening_ports": ports,
    }


def scan_file(path: str) -> Dict[str, Any]:
    """Best-effort local reputation scan plus offer a Defender quick-scan trigger."""
    info = rep.check_reputation(path)
    return {"path": path, "reputation": info}


def detect(rules_path: str, limit: int = 200) -> Dict[str, Any]:
    events = seclogs.get_security_events(limit=limit)
    rules = secrules.load_rules(rules_path)
    matches = secrules.evaluate_events(events, rules)
    return {"events": len(events), "rules": len(rules), "matches": matches}


def quarantine_file(path: str, dry_run: bool = True) -> Dict[str, Any]:
    return corefs.quarantine_paths([path], dry_run=dry_run)
