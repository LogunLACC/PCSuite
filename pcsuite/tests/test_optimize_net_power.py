import os
import pytest
from typer.testing import CliRunner


def test_optimize_net_recommendations(monkeypatch):
    from pcsuite.optimize import network_stack as net
    from pcsuite.core import shell

    out = """
    Querying active state...
    Receive Window Auto-Tuning Level : disabled
    Add-On Congestion Control Provider : none
    ECN Capability : disabled
    RFC 1323 Timestamps : disabled
    Receive-Side Scaling State : disabled
    """.strip()

    monkeypatch.setattr(shell, "cmdline", lambda c, timeout=None: (0, out, ""))
    cur = net.current_settings()
    recs = net.recommend(cur)
    keys = {r["key"] for r in recs}
    assert "Receive Window Auto-Tuning Level" in keys
    assert "ECN Capability" in keys
    assert "Add-On Congestion Control Provider" in keys
    assert "Receive-Side Scaling State" in keys


@pytest.mark.skipif(os.name != "nt", reason="Windows-only CLI tests")
def test_cli_power_plan_dry_run(monkeypatch):
    from pcsuite.cli.main import app
    from pcsuite.core import shell

    # Active scheme
    monkeypatch.setattr(shell, "cmdline", lambda c, timeout=None: (0, "Power Scheme GUID: 01234567-89ab-cdef-0123-456789abcdef  (Balanced)", "") if "GETACTIVESCHEME" in c else (0, "Power Scheme GUID: 11111111-1111-1111-1111-111111111111  (Balanced)\nPower Scheme GUID: 22222222-2222-2222-2222-222222222222  (High performance)", ""))
    runner = CliRunner()
    res = runner.invoke(app, ["optimize", "power-plan", "--profile", "high"])
    assert res.exit_code == 0
    assert "Dry-run" in res.output
