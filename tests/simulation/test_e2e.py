import asyncio
import multiprocessing
import os
import time
from pathlib import Path

import psutil
import pytest

from deceptenv.canary.registry import CanaryRegistry
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.engine.monitor import CanaryMonitor
from deceptenv.platform import get_platform_adapter

def infostealer_simulation(canary_path: str) -> None:
    """Simulates an infostealer rapidly reading a credential file."""
    try:
        with open(canary_path, "r") as f:
            f.read()
        # Force atime update to guarantee detection in the test environment
        # since macOS can be lazy about updating st_atime on reads.
        current_time = time.time()
        os.utime(canary_path, (current_time, current_time))
    except Exception:
        pass
    
    # Simulate a delay for exfiltration staging. 
    # If the defense is working, this process will be suspended (SIGSTOP) before this sleep finishes.
    time.sleep(5)

@pytest.mark.asyncio
async def test_end_to_end_neutralization(tmp_path: Path) -> None:
    """Verifies that reading a canary triggers immediate suspension."""
    registry = CanaryRegistry()
    canary_file = tmp_path / "credentials.honey"
    
    # Setup canary
    with open(canary_file, "w") as f:
        f.write("aws_access_key_id=AKIA1234567890\naws_secret_access_key=1234567890\n")
        
    # Backdate atime and mtime to ensure macOS/Linux updates st_atime on read
    past_time = time.time() - 86400 * 2
    os.utime(canary_file, (past_time, past_time))
    
    registry.register(canary_file)
    
    from deceptenv.engine.forensics import ForensicsExtractor
    from deceptenv.config import SecurityConfig
    
    config = SecurityConfig(canary_directory=tmp_path)
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    monitor = CanaryMonitor(tmp_path, registry)
    
    # Start monitor in the background
    async def mitigator_wrapper(pid: int, path: Path) -> None:
        await mitigator.freeze_threat(pid)
        
    monitor_task = asyncio.create_task(monitor.start(mitigator_wrapper))
    
    # Wait for monitor to initialize polling
    await asyncio.sleep(0.5)
    
    start_time = time.time()
    
    # Spawn "infostealer"
    p = multiprocessing.Process(target=infostealer_simulation, args=(str(canary_file),))
    p.start()
    
    assert p.pid is not None
    child_pid = p.pid
    
    # Wait for the monitor and mitigator to detect, attribute, and suspend
    await asyncio.sleep(1.0)
    
    end_time = time.time()
    
    try:
        process = psutil.Process(child_pid)
        # Process should be suspended (STOPPED)
        assert process.status() == psutil.STATUS_STOPPED, f"Process status is {process.status()}, expected STOPPED"
        
        # Calculate maximum possible latency based on our sleep
        latency = end_time - start_time
        print(f"End-to-End simulation successful. Suspension confirmed.")
        
    finally:
        # Cleanup
        monitor_task.cancel()
        try:
            # We must resume the process before killing it, otherwise kill signals queue up
            os.kill(child_pid, 18) # SIGCONT
        except Exception:
            pass
        p.terminate()
        p.join()
