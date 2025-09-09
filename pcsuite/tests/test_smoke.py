import os
from pathlib import Path

from typer.testing import CliRunner


def test_cli_help_runs():
    from pcsuite.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Commands" in result.output


def test_enumerate_targets_uses_temp_env(monkeypatch, tmp_path):
    # Point environment to a temp sandbox
    temp_dir = tmp_path / "Temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    local_app = tmp_path / "LocalAppData"
    (local_app / "Temp").mkdir(parents=True, exist_ok=True)
    win_dir = tmp_path / "Windows"
    (win_dir / "Temp").mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("TEMP", str(temp_dir))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app))
    monkeypatch.setenv("WINDIR", str(win_dir))

    # Create a file in %TEMP%
    target = temp_dir / "sample.tmp"
    target.write_text("x", encoding="utf-8")

    from pcsuite.core import fs

    targets = fs.enumerate_targets(["temp"])
    assert any(t.path == str(target) for t in targets)


def test_cleanup_and_rollback(monkeypatch, tmp_path):
    # Isolate reports to tmp cwd
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

    res = fs.execute_cleanup(["temp"])
    assert res["moved"] >= 1
    assert Path(res["cleanup_report"]).exists()
    assert Path(res["rollback_file"]).exists()
    assert not src_file.exists()  # should be moved to quarantine

    # Now rollback
    rres = fs.execute_rollback(res["rollback_file"])
    assert rres["restored"] >= 1
    assert Path(rres["restore_report"]).exists()
    assert src_file.exists()

def test_dry_run_cleanup_and_rollback(monkeypatch, tmp_path):
    # Isolate to tmp cwd
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
    src_file = temp_dir / "to_clean_dry.txt"
    src_file.write_text("data", encoding="utf-8")

    from pcsuite.core import fs

    # Dry-run cleanup: should not move file
    res = fs.execute_cleanup(["temp"], dry_run=True)
    assert res["dry_run"] is True
    assert res["moved"] >= 1
    assert res["rollback_file"] is None
    assert Path(res["cleanup_report"]).name.startswith("cleanup_dryrun_")
    assert src_file.exists()

    # Create a real rollback mapping by doing a real cleanup for the same file
    res_real = fs.execute_cleanup(["temp"], dry_run=False)
    assert not src_file.exists()

    # Dry-run rollback: should not restore file
    rres = fs.execute_rollback(res_real["rollback_file"], dry_run=True)
    assert rres["dry_run"] is True
    assert Path(rres["restore_report"]).name.startswith("restore_dryrun_")
    assert not src_file.exists()
