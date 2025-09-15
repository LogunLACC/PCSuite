from __future__ import annotations
import os
import yaml
import win32serviceutil
import win32service
import win32event
import servicemanager
from pathlib import Path
from typing import Any, Dict

from pcsuite.agent.runner import Agent, DEFAULT_INTERVAL


def _config_path() -> Path:
    root = os.environ.get("ProgramData") or r"C:\\ProgramData"
    base = Path(root) / "PCSuite" / "agent"
    base.mkdir(parents=True, exist_ok=True)
    return base / "agent.yml"


def load_config() -> Dict[str, Any]:
    cfg = {"interval": DEFAULT_INTERVAL, "sources": ["security", "powershell"], "rules": None}
    p = _config_path()
    if p.exists():
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                cfg.update(data)
        except Exception:
            pass
    return cfg


class PCSuiteEDRService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PCSuiteEDRAgent"
    _svc_display_name_ = "PCSuite EDR Agent"
    _svc_description_ = "Background agent that watches Windows event logs and evaluates rules."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.agent:
            try:
                self.agent.stop()
            except Exception:
                pass
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        cfg = load_config()
        self.agent = Agent(rules_path=cfg.get("rules"), interval=cfg.get("interval"), sources=cfg.get("sources"))
        # Run agent loop; block until stop event is signaled
        import threading
        t = threading.Thread(target=self.agent.run_forever, daemon=True)
        t.start()
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        servicemanager.LogInfoMsg("PCSuite EDR Agent stopped")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(PCSuiteEDRService)

