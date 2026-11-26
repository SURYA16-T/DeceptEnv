import asyncio
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple

import psutil

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicReport, ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.engine.monitor import CanaryMonitor


async def run_simulation() -> None:
    """Run a full monitor -> attribute -> freeze -> forensics attack simulation in an isolated sandbox."""
    with tempfile.TemporaryDirectory(prefix="deceptenv_sim_") as tmp_dir:
        sandbox_root = Path(tmp_dir)
        canary_dir = sandbox_root / "canaries"
        canary_dir.mkdir(parents=True, exist_ok=True)

        config = SecurityConfig(canary_directory=canary_dir)
        deployer = CanaryDeployer(config.canary_directory)
        registry = CanaryRegistry()

        # Deploy isolated canaries in sandbox
        env_path = deployer.deploy_env_file()
        registry.register(env_path)

        forensics = ForensicsExtractor(config)
        mitigator = ThreatMitigator(forensics)
        monitor = CanaryMonitor(canary_dir, registry)

        print(f"[*] Deployed sandbox canary at {env_path}")

        events: list[Tuple[int, Path, Optional[ForensicReport], float]] = []

        async def on_threat(pid: int, path: Path) -> None:
            t0 = time.time()
            report = await mitigator.freeze_threat(pid)
            elapsed_ms = (time.time() - t0) * 1000.0
            events.append((pid, path, report, elapsed_ms))

        monitor_task = asyncio.create_task(monitor.start(on_threat))
        await asyncio.sleep(0.3)

        print("[*] Spawning real unmodified infostealer child process...")

        script_path = sandbox_root / "rogue_stealer.py"
        script_content = f"""
import time
def run() -> None:
    with open(r"{env_path}", "rb") as f:
        _ = f.read()
    print("CANARY_READ", flush=True)
    time.sleep(5)
    print("Exfiltration Complete", flush=True)
if __name__ == "__main__":
    run()
"""
        script_path.write_text(script_content)

        proc = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            if proc.stdout is not None:
                ready_line = proc.stdout.readline()
                assert "CANARY_READ" in ready_line, (
                    "Child process failed to read canary."
                )

            for _ in range(40):
                if events:
                    break
                await asyncio.sleep(0.05)

            assert events, "CanaryMonitor did not detect real canary read!"
            pid, tripped_path, report, freeze_ms = events[0]
            assert pid == proc.pid, f"Expected PID {proc.pid}, got {pid}"
            assert report is not None, (
                "ThreatMitigator failed to generate a forensic report!"
            )

            print(f"[*] Monitor intercepted read on {tripped_path.name} -> froze PID {pid}")
            print(f"[+] Forensic Report Extracted:\n{report.model_dump_json(indent=2)}")
            print(f"[+] Scheduler freeze completed in {freeze_ms:.2f}ms")

            assert psutil.Process(proc.pid).status() == psutil.STATUS_STOPPED
            print("[*] Verifying frozen process stays suspended for 2s...")
            await asyncio.sleep(2.0)
            assert proc.poll() is None, "Process terminated instead of staying frozen!"
        finally:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
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

        print("[+] SUCCESS: Real-read infostealer simulation completely neutralized.")


if __name__ == "__main__":
    asyncio.run(run_simulation())
