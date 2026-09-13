import os
import sqlite3
import threading
from pathlib import Path

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
import pytest
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
    
def test_canary_deployer_chrome_cookies(tmp_path: Path) -> None:
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
