from typer.testing import CliRunner


def test_registry_preview_shape():
    from pcsuite.core import registry

    data = registry.registry_preview()
    assert isinstance(data, dict)
    targets = data.get("targets")
    assert isinstance(targets, list)
    assert all(isinstance(t, dict) and {"key", "values", "subkeys"} <= set(t.keys()) for t in targets)


def test_drivers_list_cli_outputs_table():
    from pcsuite.cli.main import app

    runner = CliRunner()
    res = runner.invoke(app, ["drivers", "list"])
    assert res.exit_code == 0
    # Should contain the table title
    assert "Installed Drivers (pnputil)" in res.output

