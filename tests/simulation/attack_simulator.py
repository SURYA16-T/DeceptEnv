import asyncio
import subprocess
import sys
import time
from pathlib import Path

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator


async def run_simulation() -> None:
    config = SecurityConfig(canary_directory=Path("/tmp/deceptenv_sim"))
    deployer = CanaryDeployer(config.canary_directory)
    registry = CanaryRegistry()
    
    # Deploy canary
    aws_path = deployer.deploy_aws_credentials()
    registry.register(aws_path)
    
    sys_path = deployer.deploy_system_config()
    registry.register(sys_path)
    
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    
    print(f"[*] Deployed AWS canary at {aws_path}")
    print("[*] Spawning infostealer child process...")
    
    # Write the rogue script to a temporary file
    script_path = Path("/tmp/rogue_stealer.py")
    script_content = f"""
import time
def run() -> None:
    try:
        with open("{sys_path}", "rb") as f:
            f.read()
    except Exception:
        pass
    print("READY", flush=True)
    time.sleep(5)
    print("Exfiltration Complete", flush=True)
if __name__ == "__main__":
    run()
"""
    script_path.write_text(script_content)
    
    # Spawn child process
    proc = subprocess.Popen(
        [sys.executable, str(script_path)], 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for the process to actually open the file and signal READY
    if proc.stdout is not None:
        ready_line = proc.stdout.readline()
        assert "READY" in ready_line, "Child process failed to initialize and read canary."
    
    print(f"[*] Attributed threat to PID {proc.pid}. Initiating freeze...")
    
    mitigate_start = time.time()
    report = await mitigator.freeze_threat(proc.pid)
    mitigate_duration = time.time() - mitigate_start
    
    assert report is not None, "ThreatMitigator failed to generate a forensic report!"
    print(f"[+] Forensic Report Extracted:\n{report.model_dump_json(indent=2)}")
    
    print(f"[+] Process suspended in {mitigate_duration * 1000:.2f}ms")
    assert mitigate_duration < 0.05, f"Suspension took {mitigate_duration*1000}ms, which is > 50ms!"
    
    # Now check if it wakes up
    print("[*] Waiting 6 seconds to verify it never finishes the sleep...")
    time.sleep(6)
    
    # Try to poll the process
    status = proc.poll()
    assert status is None, f"Process terminated unexpectedly with status {status}. It should be frozen!"
    
    # Clean up and check stdout
    proc.kill()
    proc.wait()
    
    stdout, _ = proc.communicate()
    assert "Exfiltration Complete" not in stdout, "Infostealer successfully completed exfiltration!"
    
    print("[+] SUCCESS: Infostealer simulation completely neutralized.")

if __name__ == "__main__":
    asyncio.run(run_simulation())
