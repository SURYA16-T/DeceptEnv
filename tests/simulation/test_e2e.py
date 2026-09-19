import asyncio
import multiprocessing
import os
import signal
import time
from pathlib import Path

import psutil
import pytest

from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.engine.monitor import CanaryMonitor


def infostealer_simulation(canary_path: str) -> None:
    """Simulates an infostealer rapidly reading a credential file."""
    try:
        with open(canary_path, "r") as f:
            f.read()
        current_time = time.time()
        os.utime(canary_path, (current_time, current_time))
    except Exception:
        pass  # noqa: S110
    time.sleep(5)


def negative_unrelated_file_simulation(file_path: str) -> None:
    """Simulates reading a file that is not a canary."""
    try:
        with open(file_path, "r") as f:
            f.read()
        current_time = time.time()
        os.utime(file_path, (current_time, current_time))
    except Exception:
        pass  # noqa: S110
    time.sleep(1)


from typing import Any, Tuple


async def setup_test_env(tmp_path: Path) -> Tuple[Any, ...]:
    registry = CanaryRegistry()
    canary_file = tmp_path / "credentials.honey"
    with open(canary_file, "w") as f:
        f.write("aws_access_key_id=AKIA1234567890\naws_secret_access_key=1234567890\n")

    past_time = time.time() - 86400 * 2
    os.utime(canary_file, (past_time, past_time))
    registry.register(canary_file)

    config = SecurityConfig(canary_directory=tmp_path)
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    monitor = CanaryMonitor(tmp_path, registry)

    return registry, canary_file, mitigator, monitor


@pytest.mark.asyncio
async def test_end_to_end_neutralization(tmp_path: Path) -> None:
    """Verifies that reading a canary triggers immediate suspension."""
    registry, canary_file, mitigator, monitor = await setup_test_env(tmp_path)

    async def mitigator_wrapper(pid: int, path: Path) -> None:
        await mitigator.freeze_threat(pid)

    monitor_task = asyncio.create_task(monitor.start(mitigator_wrapper))
    await asyncio.sleep(0.5)

    p = multiprocessing.Process(target=infostealer_simulation, args=(str(canary_file),))
    p.start()

    assert p.pid is not None
    child_pid = p.pid

    await asyncio.sleep(1.0)

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

    mitigated_pids = []

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

    await asyncio.sleep(1.0)

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
    """Measures latency of access, telemetry, attribution, and suspension."""
    registry, canary_file, mitigator, monitor = await setup_test_env(tmp_path)

    latencies = []

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

    await asyncio.sleep(1.0)

    try:
        if latencies:
            t_telemetry, t_suspension = latencies[0]
            total_latency = (t_suspension - start_time) * 1000
            print("\\n--- BENCHMARK RESULTS ---")
            print(f"Total Simulation Latency (Start -> Frozen): {total_latency:.2f} ms")
        else:
            print("Failed to capture latency")

    finally:
        monitor_task.cancel()
        try:
            if child_pid is not None:
                os.kill(child_pid, signal.SIGCONT)
        except Exception:
            pass  # noqa: S110
        p.terminate()
        p.join()
