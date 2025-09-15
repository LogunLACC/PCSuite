from __future__ import annotations
import os
import time
import threading
from pathlib import Path
from typing import List

from pcsuite.security import logs as seclogs
from pcsuite.security import rules as secrules
from pcsuite.security import edr as edrsec
import json
import platform
from urllib import request as urlreq, error as urlerr


DEFAULT_INTERVAL = 2.0
DEFAULT_SOURCES = ("security", "powershell")
DEFAULT_RULES = str((Path(__file__).parents[2] / "data" / "rules").resolve())


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _log_path() -> Path:
    root = os.environ.get("ProgramData") or r"C:\\ProgramData"
    base = Path(root) / "PCSuite" / "agent"
    _ensure_dir(base)
    return base / "agent.log"


def _write_lines(lines: List[str]) -> None:
    logf = _log_path()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(logf, "a", encoding="utf-8") as f:
        for ln in lines:
            f.write(f"[{ts}] {ln}\n")


class Agent:
    def __init__(self, rules_path: str | None = None, interval: float = DEFAULT_INTERVAL, sources: List[str] | None = None,
                 http_sink: dict | None = None, heartbeat_interval: float | None = None, auto_response: dict | None = None):
        self.rules_path = rules_path or DEFAULT_RULES
        self.interval = float(interval or DEFAULT_INTERVAL)
        s = sources or list(DEFAULT_SOURCES)
        self.sources = {x.strip().lower() for x in s}
        self._stop = threading.Event()
        self._last = {"security": 0, "powershell": 0}
        self._rules = secrules.load_rules(self.rules_path)
        self.http_sink = http_sink or {}
        self.hb_interval = float(heartbeat_interval or 0)
        self._last_hb = 0.0
        self.auto_response = auto_response or {"enabled": False}

    def run_once(self) -> None:
        evs = []
        if "security" in self.sources:
            d, self._last["security"] = seclogs.delta_security_events(self._last["security"])
            evs.extend(d)
        if "powershell" in self.sources:
            d, self._last["powershell"] = seclogs.delta_powershell_events(self._last["powershell"])
            evs.extend(d)
        if not evs:
            return
        matches = secrules.evaluate_events(evs, self._rules)
        if matches:
            lines = [f"match: {m.get('rule')} count={m.get('count')}" for m in matches]
            _write_lines(lines)
            self._send_alerts(matches)
            self._maybe_respond(matches)

    def run_forever(self) -> None:
        _write_lines([f"Agent starting (rules={self.rules_path}, sources={','.join(sorted(self.sources))}, interval={self.interval})"])
        try:
            while not self._stop.is_set():
                try:
                    self.run_once()
                except Exception as e:
                    _write_lines([f"error: {e}"])
                # Heartbeat
                now = time.time()
                if self.hb_interval and (now - self._last_hb) >= self.hb_interval:
                    try:
                        self._send_heartbeat()
                    finally:
                        self._last_hb = now
                self._stop.wait(self.interval if self.interval > 0.2 else 0.2)
        finally:
            _write_lines(["Agent stopping"])

    def stop(self) -> None:
        self._stop.set()


def run_agent(rules_path: str | None = None, interval: float = DEFAULT_INTERVAL, sources: List[str] | None = None):
    Agent(rules_path=rules_path, interval=interval, sources=sources).run_forever()

    # Helper methods
    
    def _sink_enabled(self) -> bool:
        return bool(self.http_sink.get("url"))

    def _post_json(self, payload: dict) -> None:
        if not self._sink_enabled():
            return
        url = self.http_sink.get("url")
        token = self.http_sink.get("token")
        verify = self.http_sink.get("verify", True)
        timeout = float(self.http_sink.get("timeout", 3))
        data = json.dumps(payload).encode("utf-8")
        req = urlreq.Request(url, data=data, headers={"Content-Type": "application/json"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            # urllib does not handle verify flag directly; rely on OS certs unless custom context is needed.
            urlreq.urlopen(req, timeout=timeout)
        except urlerr.URLError as e:
            _write_lines([f"sink error: {e}"])

    def _send_alerts(self, matches: list[dict]) -> None:
        if not matches:
            return
        payload = {
            "type": "alerts",
            "host": platform.node(),
            "os": platform.platform(),
            "matches": matches,
            "ts": time.time(),
        }
        self._post_json(payload)

    def _send_heartbeat(self) -> None:
        payload = {
            "type": "heartbeat",
            "host": platform.node(),
            "os": platform.platform(),
            "ts": time.time(),
        }
        self._post_json(payload)

    def _maybe_respond(self, matches: list[dict]) -> None:
        cfg = self.auto_response or {}
        if not cfg.get("enabled"):
            return
        # Rule-specific response takes precedence
        for m in matches:
            resp = m.get("response")
            if isinstance(resp, dict):
                act = str(resp.get("action") or "").lower()
                if act == "isolate":
                    riso = resp.get("isolate") or {}
                    try:
                        edrsec.isolate(
                            enable=True,
                            dry_run=bool(riso.get("dry_run", True)),
                            block_outbound=bool(riso.get("block_outbound", True)),
                            allow_hosts=riso.get("extra_hosts") or [],
                            presets=riso.get("presets") or [],
                            dns_ttl=float(riso.get("dns_ttl", 3600.0)),
                        )
                        _write_lines([f"auto-response: rule isolate ({m.get('rule')})"])
                        return
                    except Exception as e:
                        _write_lines([f"auto-response error (rule): {e}"])
        # Fallback: global policy on high/critical or generic action
        do_isolate = False
        for m in matches:
            sev = str(m.get("severity") or "").lower()
            act = str(m.get("action") or "").lower()
            if act == "isolate" or sev in ("critical", "high"):
                do_isolate = True; break
        if not do_isolate:
            return
        iso = cfg.get("isolate") or {}
        try:
            edrsec.isolate(
                enable=True,
                dry_run=bool(iso.get("dry_run", True)),
                block_outbound=bool(iso.get("block_outbound", True)),
                allow_hosts=iso.get("extra_hosts") or [],
                presets=iso.get("presets") or [],
                dns_ttl=float(iso.get("dns_ttl", 3600.0)),
            )
            _write_lines(["auto-response: isolation triggered (global)"])
        except Exception as e:
            _write_lines([f"auto-response error (global): {e}"])
