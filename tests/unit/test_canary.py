import os
import sqlite3
import threading
from pathlib import Path

import pytest

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.exceptions import SecurityBoundaryViolation


def test_canary_registry_thread_safety(tmp_path: Path) -> None:
    registry = CanaryRegistry()

    files = []
    for i in range(100):
        f = tmp_path / f"test_{i}.txt"
        f.write_text("dummy")
        files.append(f)

    def worker(paths: list[Path]) -> None:
        for p in paths:
            registry.register(p)

    chunks = [files[i::4] for i in range(4)]
    threads = []
    for chunk in chunks:
        t = threading.Thread(target=worker, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    for f in files:
        assert registry.is_canary(f)


def test_canary_deployer_aws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    deployer = CanaryDeployer(tmp_path)
    aws_file = deployer.deploy_aws_credentials()

    assert aws_file.exists()
    assert aws_file.name == "credentials.honey"
    assert (tmp_path / ".aws" / "credentials.honey").exists()

    stat = os.stat(aws_file)
    assert (stat.st_mode & 0o777) == 0o600


def test_canary_deployer_chrome_cookies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    deployer = CanaryDeployer(tmp_path)
    cookie_file = deployer.deploy_chrome_cookies()

    assert cookie_file.exists()
    assert cookie_file.name == "Cookies.honey"

    with sqlite3.connect(cookie_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT host_key FROM cookies")
        rows = cursor.fetchall()

    hosts = [r[0] for r in rows]
    assert ".google.com" in hosts
    assert ".github.com" in hosts

    stat = os.stat(cookie_file)
    assert (stat.st_mode & 0o777) == 0o600


def test_canary_deployer_env_file(tmp_path: Path) -> None:
    deployer = CanaryDeployer(tmp_path)
    env_file = deployer.deploy_env_file()

    assert env_file.exists()
    assert env_file.name == ".env.honey"

    content = env_file.read_text()
    assert "OPENAI_API_KEY" in content

    stat = os.stat(env_file)
    assert (stat.st_mode & 0o777) == 0o600


def test_canary_deployer_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that deploying canaries multiple times does not append duplicate extensions or crash."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    deployer = CanaryDeployer(tmp_path)

    # First deployment
    aws1 = deployer.deploy_aws_credentials()
    chrome1 = deployer.deploy_chrome_cookies()
    env1 = deployer.deploy_env_file()
    sys1 = deployer.deploy_system_config()

    # Second deployment
    aws2 = deployer.deploy_aws_credentials()
    chrome2 = deployer.deploy_chrome_cookies()
    env2 = deployer.deploy_env_file()
    sys2 = deployer.deploy_system_config()

    # Third deployment
    aws3 = deployer.deploy_aws_credentials()
    chrome3 = deployer.deploy_chrome_cookies()
    env3 = deployer.deploy_env_file()
    sys3 = deployer.deploy_system_config()

    assert aws1 == aws2 == aws3
    assert aws1.name == "credentials.honey"
    assert chrome1 == chrome2 == chrome3
    assert chrome1.name == "Cookies.honey"
    assert env1 == env2 == env3
    assert env1.name == ".env.honey"
    assert sys1 == sys2 == sys3


def test_canary_deployer_static_resolvers(tmp_path: Path) -> None:
    aws_path = CanaryDeployer.get_aws_credentials_path()
    assert aws_path.name == "credentials.honey"

    chrome_path = CanaryDeployer.get_chrome_cookies_path(tmp_path)
    assert chrome_path.name == "Cookies.honey"

    sys_path = CanaryDeployer.get_system_config_path()
    assert sys_path.name.endswith(".honey")

    env_path = CanaryDeployer.get_env_file_path(tmp_path)
    assert env_path == tmp_path / ".env.honey"


def test_canary_deployer_boundary_violation(tmp_path: Path) -> None:
    from unittest.mock import patch

    deployer = CanaryDeployer(tmp_path / "sub")
    with patch.object(
        deployer,
        "get_env_file_path",
        return_value=tmp_path / "other" / ".env.honey",
    ):
        with pytest.raises(SecurityBoundaryViolation):
            deployer.deploy_env_file()


def test_canary_deployer_generate_token(tmp_path: Path) -> None:
    deployer = CanaryDeployer(tmp_path)
    token = deployer.generate_token()
    assert isinstance(token, str)
    assert len(token) == 64
