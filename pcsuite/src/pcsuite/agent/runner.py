from __future__ import annotations
import os
import time
import threading
from pathlib import Path
from typing import List

from pcsuite.security import logs as seclogs
from pcsuite.security import rules as secrules


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
    def __init__(self, rules_path: str | None = None, interval: float = DEFAULT_INTERVAL, sources: List[str] | None = None):
        self.rules_path = rules_path or DEFAULT_RULES
        self.interval = float(interval or DEFAULT_INTERVAL)
        s = sources or list(DEFAULT_SOURCES)
        self.sources = {x.strip().lower() for x in s}
        self._stop = threading.Event()
        self._last = {"security": 0, "powershell": 0}
        self._rules = secrules.load_rules(self.rules_path)

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

    def run_forever(self) -> None:
        _write_lines([f"Agent starting (rules={self.rules_path}, sources={','.join(sorted(self.sources))}, interval={self.interval})"])
        try:
            while not self._stop.is_set():
                try:
                    self.run_once()
                except Exception as e:
                    _write_lines([f"error: {e}"])
                self._stop.wait(self.interval if self.interval > 0.2 else 0.2)
        finally:
            _write_lines(["Agent stopping"])

    def stop(self) -> None:
        self._stop.set()


def run_agent(rules_path: str | None = None, interval: float = DEFAULT_INTERVAL, sources: List[str] | None = None):
    Agent(rules_path=rules_path, interval=interval, sources=sources).run_forever()

