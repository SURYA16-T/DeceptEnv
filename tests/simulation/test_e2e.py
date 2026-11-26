import asyncio
import multiprocessing
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, List, Optional, Tuple

import psutil
import pytest

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicReport, ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.engine.monitor import CanaryMonitor


def infostealer_simulation(canary_path: str) -> None:
    """Simulates a real infostealer reading a credential file without touching timestamps."""
    try:
        with open(canary_path, "r") as f:
            _ = f.read()
    except Exception:
        pass  # noqa: S110
    time.sleep(5)


def negative_unrelated_file_simulation(file_path: str) -> None:
    """Simulates reading a non-canary file."""
    try:
        with open(file_path, "r") as f:
            _ = f.read()
    except Exception:
        pass  # noqa: S110
    time.sleep(1)


async def setup_test_env(tmp_path: Path) -> Tuple[Any, ...]:
    registry = CanaryRegistry()
    canary_file = tmp_path / "credentials.honey"
    with open(canary_file, "w") as f:
        f.write("aws_access_key_id=AKIA1234567890\naws_secret_access_key=1234567890\n")

    registry.register(canary_file)

    config = SecurityConfig(canary_directory=tmp_path)
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    monitor = CanaryMonitor(tmp_path, registry)

    return registry, canary_file, mitigator, monitor


@pytest.mark.asyncio
async def test_end_to_end_neutralization(tmp_path: Path) -> None:
    """Verifies that a natural read (no utime helper) of a canary triggers immediate SIGSTOP."""
    registry, canary_file, mitigator, monitor = await setup_test_env(tmp_path)

    async def mitigator_wrapper(pid: int, path: Path) -> None:
        await mitigator.freeze_threat(pid)

    monitor_task = asyncio.create_task(monitor.start(mitigator_wrapper))
    await asyncio.sleep(0.5)

    p = multiprocessing.Process(target=infostealer_simulation, args=(str(canary_file),))
    p.start()

    assert p.pid is not None
    child_pid = p.pid

    for _ in range(40):
        try:
            if psutil.Process(child_pid).status() == psutil.STATUS_STOPPED:
                break
        except psutil.NoSuchProcess:
            break
        await asyncio.sleep(0.05)

    try:
        process = psutil.Process(child_pid)
        assert process.status() == psutil.STATUS_STOPPED, (
            f"Process status is {process.status()}, expected STOPPED"
        )
    finally:
        monitor_task.cancel()
        try:
            if child_pid is not None:
                os.kill(child_pid, signal.SIGCONT)
        except Exception:
            pass  # noqa: S110
        p.terminate()
        p.join()


@pytest.mark.asyncio
async def test_negative_unrelated_file(tmp_path: Path) -> None:
    """Verifies that reading an unrelated file does not trigger suspension."""
    registry, canary_file, mitigator, monitor = await setup_test_env(tmp_path)

    unrelated_file = tmp_path / "normal_file.txt"
    with open(unrelated_file, "w") as f:
        f.write("normal content")

    mitigated_pids: List[int] = []

    async def mitigator_wrapper(pid: int, path: Path) -> None:
        mitigated_pids.append(pid)

    monitor_task = asyncio.create_task(monitor.start(mitigator_wrapper))
    await asyncio.sleep(0.5)

    p = multiprocessing.Process(
        target=negative_unrelated_file_simulation, args=(str(unrelated_file),)
    )
    p.start()

    assert p.pid is not None
    child_pid = p.pid

    await asyncio.sleep(0.6)

    try:
        assert child_pid not in mitigated_pids
        process = psutil.Process(child_pid)
        assert process.status() != psutil.STATUS_STOPPED
    finally:
        monitor_task.cancel()
        p.terminate()
        p.join()


@pytest.mark.asyncio
async def test_end_to_end_latency_benchmark(tmp_path: Path) -> None:
    """Measures real-read latency of access, telemetry, attribution, and suspension."""
    registry, canary_file, mitigator, monitor = await setup_test_env(tmp_path)

    latencies: List[Tuple[float, float]] = []

    async def mitigator_wrapper(pid: int, path: Path) -> None:
        t_telemetry = time.time()
        await mitigator.freeze_threat(pid)
        t_suspension = time.time()
        latencies.append((t_telemetry, t_suspension))

    monitor_task = asyncio.create_task(monitor.start(mitigator_wrapper))
    await asyncio.sleep(0.5)

    start_time = time.time()
    p = multiprocessing.Process(target=infostealer_simulation, args=(str(canary_file),))
    p.start()
    child_pid = p.pid

    for _ in range(40):
        if latencies:
            break
        await asyncio.sleep(0.05)

    try:
        assert latencies, "Monitor/Mitigator failed to intercept simulated infostealer"
        t_telemetry, t_suspension = latencies[0]
        total_latency = (t_suspension - start_time) * 1000
        print("\n--- BENCHMARK RESULTS ---")
        print(f"Total Simulation Latency (Start -> Frozen): {total_latency:.2f} ms")
    finally:
        monitor_task.cancel()
        try:
            if child_pid is not None:
                os.kill(child_pid, signal.SIGCONT)
        except Exception:
            pass  # noqa: S110
        p.terminate()
        p.join()


@pytest.mark.asyncio
async def test_sandboxed_attacker_exfiltration_blocked_with_forensics(
    tmp_path: Path,
) -> None:
    """Full sandbox proof: real read without utime gets frozen, forensics captured, exfiltration blocked."""
    canary_dir = tmp_path / "sandbox_canaries"
    canary_dir.mkdir(parents=True, exist_ok=True)
    deployer = CanaryDeployer(canary_dir)
    env_canary = deployer.deploy_env_file()

    registry = CanaryRegistry()
    registry.register(env_canary)

    config = SecurityConfig(canary_directory=canary_dir)
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    monitor = CanaryMonitor(canary_dir, registry)

    captured_reports: List[Tuple[int, Path, Optional[ForensicReport]]] = []

    async def mitigator_wrapper(pid: int, path: Path) -> None:
        report = await mitigator.freeze_threat(pid)
        captured_reports.append((pid, path, report))

    monitor_task = asyncio.create_task(monitor.start(mitigator_wrapper))
    await asyncio.sleep(0.4)

    # Genuine attacker payload: ONLY reads the canary file (no utime manipulation)
    attacker_script = tmp_path / "attacker_payload.py"
    attacker_script.write_text(
        f"""
import time
target = r"{env_canary}"
with open(target, "rb") as f:
    stolen = f.read()
print("CANARY_READ:" + str(len(stolen)), flush=True)
time.sleep(5)
print("EXFILTRATION_SUCCEEDED", flush=True)
"""
    )

    proc = subprocess.Popen(
        [sys.executable, str(attacker_script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        if proc.stdout:
            line = proc.stdout.readline()
            assert "CANARY_READ:" in line

        for _ in range(40):
            if captured_reports:
                break
            await asyncio.sleep(0.05)

        assert captured_reports, "Real read of .env.honey was not intercepted!"
        mitigated_pid, tripped_path, report = captured_reports[0]
        assert mitigated_pid == proc.pid
        assert tripped_path.resolve() == env_canary.resolve()
        assert report is not None
        assert len(report.lineage) >= 1
        assert report.lineage[0].pid == proc.pid

        # Verify attacker process is frozen in scheduler (SIGSTOP -> STOPPED)
        ps_proc = psutil.Process(proc.pid)
        assert ps_proc.status() == psutil.STATUS_STOPPED
        assert proc.poll() is None

        # Verify a second consecutive natural read after debounce is ALSO caught cleanly
        monitor.debouncer.clear()
        attacker2 = subprocess.Popen(
            [sys.executable, str(attacker_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            if attacker2.stdout:
                _ = attacker2.stdout.readline()
            for _ in range(40):
                if len(captured_reports) >= 2:
                    break
                await asyncio.sleep(0.05)
            assert len(captured_reports) >= 2, "Second natural read was missed!"
            assert captured_reports[1][0] == attacker2.pid
            assert psutil.Process(attacker2.pid).status() == psutil.STATUS_STOPPED
        finally:
            if attacker2.poll() is None:
                try:
                    os.kill(attacker2.pid, signal.SIGCONT)
                except OSError:
                    pass  # noqa: S110
                attacker2.kill()
                attacker2.wait(timeout=2)

        # Kill frozen process #1 and verify exfiltration never ran
        os.kill(proc.pid, signal.SIGCONT)
        proc.kill()
        stdout_rest, _ = proc.communicate(timeout=2)
        assert "EXFILTRATION_SUCCEEDED" not in stdout_rest
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGCONT)
            except Exception:
                pass  # noqa: S110
            proc.kill()
            proc.wait(timeout=2)
