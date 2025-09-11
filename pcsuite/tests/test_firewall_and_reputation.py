import os
import pytest
from typer.testing import CliRunner


def test_firewall_states_parsing(monkeypatch):
    from pcsuite.security import firewall as fw

    sample = """
    Domain Profile Settings:
        State                                 ON

    Private Profile Settings:
        State                                 OFF

    Public Profile Settings:
        State                                 ON
    """.strip()

    def fake_cmd(cmd):
        return 0, sample, ""

    from pcsuite.core import shell

    monkeypatch.setattr(shell, "cmdline", lambda c, timeout=None: fake_cmd(c))
    states = fw.get_profile_states()
    assert states["Domain"] == "ON"
    assert states["Private"] == "OFF"
    assert states["Public"] == "ON"


@pytest.mark.skipif(os.name != "nt", reason="Windows-only CLI tests")
def test_cli_firewall_status(monkeypatch):
    from pcsuite.cli.main import app
    from pcsuite.core import shell

    sample = """
    Domain Profile Settings:
        State                                 ON
    Private Profile Settings:
        State                                 OFF
    Public Profile Settings:
        State                                 ON
    """.strip()

    monkeypatch.setattr(shell, "cmdline", lambda c, timeout=None: (0, sample, ""))
    runner = CliRunner()
    res = runner.invoke(app, ["security", "firewall"])  # show status
    assert res.exit_code == 0
    assert "Firewall Profiles" in res.output


def test_reputation_check(monkeypatch, tmp_path):
    from pcsuite.security import reputation as rep
    from pcsuite.core import shell

    # Create a dummy file
    f = tmp_path / "x.exe"
    f.write_text("hello", encoding="utf-8")

    # Stub signature and ADS queries
    monkeypatch.setattr(shell, "pwsh", lambda cmd, timeout=None: (0, "Valid\n", "") if "AuthenticodeSignature" in cmd else (0, "[ZoneTransfer]\nZoneId=3\n", ""))
    info = rep.check_reputation(str(f))
    assert info["signature"].lower() == "valid"
    assert info["has_zone"] is True
    assert info["zone_id"] == 3
