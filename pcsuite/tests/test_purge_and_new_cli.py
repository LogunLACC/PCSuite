import os
from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.mark.skipif(os.name != "nt", reason="Windows-only tests")
def test_purge_quarantine_flow(monkeypatch, tmp_path):
    # Isolate to tmp cwd so reports/quarantine live under tmp
    monkeypatch.chdir(tmp_path)

    # Sandbox environment variables to avoid touching real system
    temp_dir = tmp_path / "Temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    local_app = tmp_path / "LocalAppData"
    (local_app / "Temp").mkdir(parents=True, exist_ok=True)
    win_dir = tmp_path / "Windows"
    (win_dir / "Temp").mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("TEMP", str(temp_dir))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app))
    monkeypatch.setenv("WINDIR", str(win_dir))

    # Create a file to be cleaned
    src_file = temp_dir / "to_clean.txt"
    src_file.write_text("data", encoding="utf-8")

    from pcsuite.core import fs

    # Real cleanup to create quarantine
    res = fs.execute_cleanup(["temp"], dry_run=False, scope="user")
    assert res["moved"] >= 1
    # Dry-run purge should report the run but not delete it
    pdry = fs.purge_quarantine(dry_run=True)
    assert pdry["dry_run"] is True
    assert len(pdry["target_runs"]) >= 1
    assert pdry["freed_bytes"] >= 1
    # Real purge should delete the target run
    pres = fs.purge_quarantine(dry_run=False)
    assert pres["deleted_runs"] >= 1


@pytest.mark.skipif(os.name != "nt", reason="Windows-only tests")
def test_cli_clean_purge_dry_run(monkeypatch, tmp_path):
    # Isolate CWD
    monkeypatch.chdir(tmp_path)

    # Sandbox env vars
    temp_dir = tmp_path / "Temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    local_app = tmp_path / "LocalAppData"
    (local_app / "Temp").mkdir(parents=True, exist_ok=True)
    win_dir = tmp_path / "Windows"
    (win_dir / "Temp").mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("TEMP", str(temp_dir))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app))
    monkeypatch.setenv("WINDIR", str(win_dir))

    # Create a file to be cleaned
    (temp_dir / "to_clean.txt").write_text("data", encoding="utf-8")

    from pcsuite.core import fs
    from pcsuite.cli.main import app

    # Do a cleanup to create quarantine
    fs.execute_cleanup(["temp"], dry_run=False, scope="user")

    # Now run the CLI purge dry-run
    runner = CliRunner()
    res = runner.invoke(app, ["clean", "purge", "--dry-run"])
    assert res.exit_code == 0
    assert "Purge report:" in res.output


@pytest.mark.skipif(os.name != "nt", reason="Windows-only tests")
def test_cli_system_info_and_drives():
    from pcsuite.cli.main import app
    runner = CliRunner()
    r1 = runner.invoke(app, ["system", "info"])
    assert r1.exit_code == 0
    r2 = runner.invoke(app, ["system", "drives"])
    assert r2.exit_code == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows-only tests")
def test_cli_security_harden_minimal_what_if():
    from pcsuite.cli.main import app
    runner = CliRunner()
    res = runner.invoke(app, ["security", "harden", "--profile", "minimal"])
    assert res.exit_code == 0
    assert "Hardening Plan (minimal)" in res.output

