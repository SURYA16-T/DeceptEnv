import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from deceptenv.cli import app, async_run

runner = CliRunner()


def test_cli_init_list_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)

    # 1. Test init
    result_init = runner.invoke(app, ["init"])
    assert result_init.exit_code == 0
    assert "Deployed AWS Canary" in result_init.stdout
    assert "Deployed Chrome Canary" in result_init.stdout
    assert "Deployed .env Canary" in result_init.stdout
    assert "Deployed System Config Canary" in result_init.stdout

    # 2. Test list-canaries
    result_list = runner.invoke(app, ["list-canaries"])
    assert result_list.exit_code == 0
    assert "Active" in result_list.stdout

    # 3. Test clean
    result_clean = runner.invoke(app, ["clean"])
    assert result_clean.exit_code == 0
    assert "Successfully cleaned" in result_clean.stdout

    # 4. Clean again should clean 0
    result_clean_empty = runner.invoke(app, ["clean"])
    assert result_clean_empty.exit_code == 0
    assert "Successfully cleaned 0 canaries" in result_clean_empty.stdout


def test_cli_init_exception_handled() -> None:
    with patch(
        "deceptenv.canary.deployer.CanaryDeployer.deploy_aws_credentials",
        side_effect=RuntimeError("Disk failure"),
    ):
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "Failed to deploy canaries" in result.stdout


@pytest.mark.asyncio
async def test_cli_async_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)

    runner.invoke(app, ["init"])

    # Run async_run briefly then cancel
    task = asyncio.create_task(async_run())
    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass


def test_cli_run_command_keyboard_interrupt() -> None:
    with patch("deceptenv.cli.async_run", side_effect=KeyboardInterrupt):
        result = runner.invoke(app, ["run"])
        assert result.exit_code == 0
        assert "Shutting down DeceptEnv" in result.stdout
