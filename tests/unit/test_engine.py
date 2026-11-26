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


def test_forensics_extract_lineage_with_mock() -> None:
    config = SecurityConfig(canary_directory=Path("/tmp"))
    forensics = ForensicsExtractor(config)

    with patch.object(forensics.platform, "get_process_lineage", return_value=[]):
        with patch("psutil.Process") as mock_proc_cls:
            mock_proc = mock_proc_cls.return_value
            mock_proc.pid = os.getpid()
            mock_proc.ppid.return_value = os.getppid()
            mock_proc.name.return_value = "python"
            mock_proc.cmdline.return_value = ["python", "test.py"]
            lineage = forensics.extract_lineage(os.getpid())
            assert len(lineage) >= 1
            assert lineage[0].name == "python"


def test_forensics_capture_snapshot_handles_access_denied() -> None:
    config = SecurityConfig(canary_directory=Path("/tmp"))
    forensics = ForensicsExtractor(config)

    import psutil

    with patch.object(forensics.platform, "get_process_lineage", return_value=[]):
        with patch("psutil.Process", side_effect=psutil.NoSuchProcess(99999)):
            report = forensics.capture_snapshot(99999)
            assert report.lineage == []
            assert report.extracted_urls == []


@pytest.mark.asyncio
async def test_mitigator_rejects_invalid_pid() -> None:
    config = SecurityConfig(canary_directory=Path("/tmp"))
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)

    result = await mitigator.freeze_threat(0)
    assert result is None

    result = await mitigator.freeze_threat(-1)
    assert result is None


def test_mitigator_sync_instantiation_safe() -> None:
    """ThreatMitigator.__init__ must succeed cleanly outside an event loop (Python 3.9)."""
    config = SecurityConfig(canary_directory=Path("/tmp"))
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    assert mitigator._action_lock is None


@pytest.mark.asyncio
async def test_mitigator_blocks_ancestor_pid() -> None:
    config = SecurityConfig(canary_directory=Path("/tmp"))
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    with patch.object(mitigator.platform, "get_process_lineage", return_value=[4242, 1]):
        assert await mitigator.freeze_threat(4242) is None


def test_forensics_capture_snapshot_extracts_iocs(tmp_path: Path) -> None:
    config = SecurityConfig(canary_directory=tmp_path)
    forensics = ForensicsExtractor(config)

    # Construct a realistic memory payload with URL, IPv4, and long base64
    b64_sample = b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
    payload = (
        b"prefix https://evil-c2.example/exfil?id=1 192.168.100.55 "
        + b64_sample
        + b" end"
    )

    maps_file = tmp_path / "maps"
    mem_file = tmp_path / "mem"
    mem_file.write_bytes(payload)
    # Include both a skipped [vvar] entry and our readable heap slice
    maps_file.write_text(
        "ffffffffff000000-ffffffffff001000 r--p 00000000 00:00 0 [vvar]\n"
        f"00000000-{len(payload):x} rw-p 00000000 00:00 0 [heap]\n"
    )

    with patch.object(forensics, "extract_lineage", return_value=[]):
        with patch("psutil.Process") as mock_proc_cls:
            mock_proc_cls.return_value.net_connections.return_value = []
            with patch("os.name", "posix"):
                with patch("os.path.exists", return_value=True):
                    original_open = open

                    def mock_open(path: str, mode: str = "r", *a: Any, **kw: Any) -> Any:
                        if str(path).endswith("/maps"):
                            return original_open(maps_file, mode, *a, **kw)
                        if str(path).endswith("/mem"):
                            return original_open(mem_file, mode, *a, **kw)
                        return original_open(path, mode, *a, **kw)

                    with patch("builtins.open", side_effect=mock_open):
                        report = forensics.capture_snapshot(9999)

    assert "https://evil-c2.example/exfil?id=1" in report.extracted_urls
    assert "192.168.100.55" in report.extracted_ips
    assert b64_sample.decode("ascii") in report.extracted_base64
