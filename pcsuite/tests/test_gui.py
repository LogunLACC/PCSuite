import os
import time
import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only GUI tests")


class _InlineThread:
    """Minimal stand-in for threading.Thread that runs inline.

    We use this to avoid background threads during tests so we can
    assert on text widgets synchronously.
    """

    def __init__(self, target=None, daemon=None, args=None, kwargs=None):
        self._target = target
        self._args = args or []
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)


def test_gui_instantiates_and_has_core_widgets(monkeypatch):
    from pcsuite.ui.gui.app import PCSuiteGUI

    gui = PCSuiteGUI()
    try:
        gui.withdraw()  # do not show window during tests
        # Basic widgets exist
        assert hasattr(gui, "output")
        assert hasattr(gui, "sys_output")
        assert hasattr(gui, "sec_output")
        # Defaults
        assert gui.scope_var.get() in ("auto", "user", "all")
    finally:
        gui.destroy()


def test_gui_on_sys_info_uses_cli_and_updates_text(monkeypatch):
    from pcsuite.ui.gui.app import PCSuiteGUI

    # Patch threading to run synchronously for determinism
    import threading

    monkeypatch.setattr(threading, "Thread", _InlineThread)

    gui = PCSuiteGUI()
    try:
        gui.withdraw()

        # Stub the CLI call to return a simple payload
        def fake_run_cli(args):
            return 0, "SYSTEM-INFO\nCPU: test-cpu", ""

        monkeypatch.setattr(gui, "_run_cli", fake_run_cli)

        # Invoke and assert text populated
        gui.on_sys_info()
        text = gui.sys_output.get("1.0", "end").strip()
        assert "SYSTEM-INFO" in text
    finally:
        gui.destroy()

