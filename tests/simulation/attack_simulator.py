import asyncio
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator


async def run_simulation() -> None:
    """Run an isolated, sandboxed infostealer attack simulation and verify neutralization."""
    with tempfile.TemporaryDirectory(prefix="deceptenv_sim_") as tmp_dir:
        sandbox_root = Path(tmp_dir)
        canary_dir = sandbox_root / "canaries"
        canary_dir.mkdir(parents=True, exist_ok=True)

        config = SecurityConfig(canary_directory=canary_dir)
        deployer = CanaryDeployer(config.canary_directory)
        registry = CanaryRegistry()

        # Deploy canaries inside isolated sandbox
        aws_path = deployer.deploy_aws_credentials()
        registry.register(aws_path)

        sys_path = deployer.deploy_system_config()
        registry.register(sys_path)

        forensics = ForensicsExtractor(config)
        mitigator = ThreatMitigator(forensics)

        print(f"[*] Deployed AWS canary at {aws_path}")
        print("[*] Spawning infostealer child process...")

        script_path = sandbox_root / "rogue_stealer.py"
        script_content = f"""
import time
def run() -> None:
    try:
        with open(r"{sys_path}", "rb") as f:
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
            text=True,
        )

        try:
            # Wait for the process to actually open the file and signal READY
            if proc.stdout is not None:
                ready_line = proc.stdout.readline()
                assert "READY" in ready_line, (
                    "Child process failed to initialize and read canary."
                )

            print(f"[*] Attributed threat to PID {proc.pid}. Initiating freeze...")

            mitigate_start = time.time()
            report = await mitigator.freeze_threat(proc.pid)
            mitigate_duration = time.time() - mitigate_start

            assert report is not None, (
                "ThreatMitigator failed to generate a forensic report!"
            )
            print(f"[+] Forensic Report Extracted:\n{report.model_dump_json(indent=2)}")

            print(f"[+] Process suspended in {mitigate_duration * 1000:.2f}ms")
            assert mitigate_duration < 0.05, (
                f"Suspension took {mitigate_duration * 1000}ms, which is > 50ms!"
            )

            # Verify the frozen process stays suspended instead of completing sleep(5)
            print("[*] Waiting 6 seconds to verify it never finishes the sleep...")
            time.sleep(6)

            status = proc.poll()
            assert status is None, (
                f"Process terminated unexpectedly with status {status}. It should be frozen!"
            )
        finally:
            if proc.poll() is None:
                try:
                    if hasattr(signal, "SIGCONT"):
                        os.kill(proc.pid, signal.SIGCONT)
                except OSError:
                    pass  # noqa: S110
                proc.kill()
            stdout, _ = proc.communicate(timeout=2)

        assert stdout is not None and "Exfiltration Complete" not in stdout, (
            "Infostealer successfully completed exfiltration!"
        )

        print("[+] SUCCESS: Infostealer simulation completely neutralized.")


if __name__ == "__main__":
    asyncio.run(run_simulation())
