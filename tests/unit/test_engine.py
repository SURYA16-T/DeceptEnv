import asyncio
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.engine.monitor import CanaryMonitor


@pytest.mark.asyncio
async def test_mitigator_self_harm_prevention() -> None:
    config = SecurityConfig(canary_directory=Path("/tmp"))
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)

    # Passing current PID should return None
    assert await mitigator.freeze_threat(os.getpid()) is None
    # Passing parent PID should return None
    assert await mitigator.freeze_threat(os.getppid()) is None


@pytest.mark.asyncio
async def test_mitigator_race_condition() -> None:
    config = SecurityConfig(canary_directory=Path("/tmp"))
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)

    current_owner = (
        mitigator.platform._get_current_user_sid()
        if os.name == "nt" and hasattr(mitigator.platform, "_get_current_user_sid")
        else (os.getuid() if hasattr(os, "getuid") else 1000)
    )
    with patch.object(
        mitigator.platform, "get_process_owner", return_value=current_owner
    ):
        with patch.object(mitigator.platform, "freeze_pid", return_value=False):
            # Because freeze_pid returns False, it raises MitigatorRaceConditionError, which the mitigator catches and returns None
            assert await mitigator.freeze_threat(99999) is None


@pytest.mark.asyncio
async def test_monitor_debouncer(tmp_path: Path) -> None:
    # Test that duplicate events are debounced
    registry = CanaryRegistry()
    monitor = CanaryMonitor(tmp_path, registry)

    p = tmp_path / "test.honey"
    p.write_bytes(b"dummy")

    monitor.queue.put_nowait(p)
    monitor.queue.put_nowait(p)
    monitor.queue.put_nowait(p)

    called_count = 0

    async def mock_mitigator(pid: int, path: Path) -> None:
        nonlocal called_count
        called_count += 1

    registry.register(p)
    with patch.object(monitor.platform, "find_pid_accessing_file", return_value=123):
        # We manually process events for a bit
        task = asyncio.create_task(monitor._process_events(mock_mitigator))
        await asyncio.sleep(0.1)  # allow processing
        task.cancel()

    assert called_count == 1  # Should only be called once because of debouncer


def test_forensics_bounded_memory_read(tmp_path: Path) -> None:
    # 1 MB limit = 1 * 1024 * 1024
    config = SecurityConfig(
        canary_directory=Path("/tmp"), max_forensic_dump_size_bytes=1048576
    )
    forensics = ForensicsExtractor(config)

    pid = 9999
    maps_file = tmp_path / "maps"
    mem_file = tmp_path / "mem"

    # 2MB of 'A's
    mem_data = b"A" * 2 * 1024 * 1024
    mem_file.write_bytes(mem_data)

    # Start: 0, End: 2MB
    maps_content = f"00000000-{2 * 1024 * 1024:x} r-xp 00000000 00:00 0\n"
    maps_file.write_text(maps_content)

    with patch("os.name", "posix"):
        with patch("os.path.exists", return_value=True):
            # Need to store the original open function
            original_open = open

            def mock_open_file(
                path: str, mode: str = "r", *args: Any, **kwargs: Any
            ) -> Any:
                if "maps" in str(path):
                    return original_open(maps_file, mode, *args, **kwargs)
                elif "mem" in str(path):
                    return original_open(mem_file, mode, *args, **kwargs)
                return original_open(path, mode, *args, **kwargs)

            with patch("builtins.open", side_effect=mock_open_file):
                extracted = forensics.dump_memory(pid)
                # Should be exactly 1MB bounded
                assert len(extracted) == 1048576
