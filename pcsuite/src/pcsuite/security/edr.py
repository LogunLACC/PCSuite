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
import time


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


_DNS_CACHE: dict[str, tuple[float, list[str]]] = {}
_DNS_TTL_SEC = 3600.0


def _resolve_hosts(hosts: list[str] | None) -> list[str]:
    if not hosts:
        return []
    ips: list[str] = []
    try:
        import socket
        for h in hosts:
            h = (h or "").strip()
            if not h:
                continue
            # If CIDR or dot contains slash, leave as-is
            if any(ch.isalpha() for ch in h):
                # cache lookup
                ent = _DNS_CACHE.get(h)
                now = time.time()
                if ent and (now - ent[0]) < _DNS_TTL_SEC:
                    for ip in ent[1]:
                        if ip not in ips:
                            ips.append(ip)
                    continue
                try:
                    resolved: list[str] = []
                    for fam, _, _, _, sockaddr in socket.getaddrinfo(h, None):
                        ip = sockaddr[0]
                        if ip and ip not in resolved:
                            resolved.append(ip)
                    _DNS_CACHE[h] = (now, resolved)
                    for ip in resolved:
                        if ip not in ips:
                            ips.append(ip)
                except Exception:
                    _DNS_CACHE[h] = (now, [])
                    continue
            else:
                if h not in ips:
                    ips.append(h)
    except Exception:
        return ips
    return ips


def _preset_hosts(names: list[str] | None) -> list[str]:
    """Map preset names to a best-effort list of hosts to allow.

    Note: Domain lists are minimal and resolved to IPs at runtime.
    """
    presets = {
        "ntp": ["time.windows.com", "pool.ntp.org"],
        "winupdate": [
            "download.windowsupdate.com",
            "windowsupdate.microsoft.com",
            "sls.update.microsoft.com",
            "crl.microsoft.com",
        ],
        "m365-core": [
            "outlook.office365.com",
            "login.microsoftonline.com",
            "graph.microsoft.com",
            "officecdn.microsoft.com",
            "sharepoint.com",
        ],
        "microsoft-basic": [
            "time.windows.com",
            "download.windowsupdate.com",
            "sls.update.microsoft.com",
        ],
        "minimal": ["time.windows.com"],
        "teams": [
            "teams.microsoft.com",
            "statics.teams.cdn.office.net",
            "presence.teams.live.com",
        ],
        "onedrive": [
            "oneclient.sfx.ms",
            "storage.live.com",
            "oneclient.sfx.ms",
        ],
        "edge-update": [
            "msedge.api.cdp.microsoft.com",
            "edge.microsoft.com",
        ],
    }
    out: list[str] = []
    for n in (names or []):
        v = presets.get(n.strip().lower())
        if v:
            out.extend(v)
    # de-dup
    seen = set()
    uniq: list[str] = []
    for h in out:
        if h not in seen:
            uniq.append(h); seen.add(h)
    return uniq


def isolate(
    enable: bool,
    dry_run: bool = True,
    block_outbound: bool = False,
    allow_hosts: list[str] | None = None,
    presets: list[str] | None = None,
    dns_ttl: float | None = None,
) -> Dict[str, Any]:
    """High-level isolation toggle via firewall profiles.

    For now, map to fw.set_all_profiles(on/off) with dry-run default.
    In a future iteration, tighten outbound policy selectively.
    """
    # TTL override (temporarily)
    old_ttl = None
    if dns_ttl is not None:
        global _DNS_TTL_SEC
        old_ttl = _DNS_TTL_SEC
        _DNS_TTL_SEC = float(max(0.0, dns_ttl))
    try:
        if not block_outbound:
            res = fw.set_all_profiles(enable=enable, dry_run=dry_run)
            return {"ok": res.get("ok", False), "dry_run": res.get("dry_run", dry_run), "detail": res}
        # Block outbound mode with allowlist
        if enable:
            res1 = fw.set_firewall_policy(block_outbound=True, dry_run=dry_run)
            hosts = (allow_hosts or []) + _preset_hosts(presets)
            ips = _resolve_hosts(hosts)
            res2 = fw.refresh_isolation_allowlist(ips, dry_run=dry_run)
            ok = res1.get("ok", False) and res2.get("ok", False)
            return {"ok": ok, "dry_run": dry_run, "detail": {"policy": res1, "allowlist": res2}}
        else:
            # disable: restore default policy and remove group rules
            res1 = fw.set_firewall_policy(block_outbound=False, dry_run=dry_run)
            res2 = fw.refresh_isolation_allowlist([], dry_run=dry_run)
            ok = res1.get("ok", False) and res2.get("ok", False)
            return {"ok": ok, "dry_run": dry_run, "detail": {"policy": res1, "allowlist": res2}}
    finally:
        if old_ttl is not None:
            _DNS_TTL_SEC = old_ttl


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


def resolve_allowlist(allow_hosts: list[str] | None = None, presets: list[str] | None = None, dns_ttl: float | None = None) -> Dict[str, Any]:
    hosts = (allow_hosts or []) + _preset_hosts(presets)
    old_ttl = None
    if dns_ttl is not None:
        global _DNS_TTL_SEC
        old_ttl = _DNS_TTL_SEC
        _DNS_TTL_SEC = float(max(0.0, dns_ttl))
    try:
        ips = _resolve_hosts(hosts)
    finally:
        if old_ttl is not None:
            _DNS_TTL_SEC = old_ttl
    return {"hosts": hosts, "ips": ips}
