import os
import pytest
from typer.testing import CliRunner


@pytest.mark.skipif(os.name != "nt", reason="Windows-only tests")
def test_schedule_create_dry_run_wraps_cmd(monkeypatch):
    from pcsuite.cli.main import app
    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "schedule",
            "create",
            "--name",
            "\\MyTasks\\PCSuiteCleanup",
            "--when",
            "DAILY",
            "--command",
            "pcsuite clean run --category temp,browser",
            "--dry-run",
        ],
    )
    assert res.exit_code == 0
    # Should show cmd /c wrapping within the /tr quoted value
    import re
    out = res.output.replace("'", '"').replace("\n", " ")
    out = re.sub(r"\s+", " ", out)
    assert "schtasks /create" in out
    assert '/tr "cmd /c ""pcsuite clean run --category temp,browser"""' in out
