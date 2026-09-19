import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Coroutine

from deceptenv.canary.registry import CanaryRegistry
from deceptenv.platform import get_platform_adapter

logger = logging.getLogger(__name__)


class CanaryMonitor:
    """High-throughput async filesystem polling loop for true read-access tripwires."""

    def __init__(self, directory: Path, registry: CanaryRegistry) -> None:
        self.directory = directory
        self.registry = registry
        self.platform = get_platform_adapter()
        self.queue: asyncio.Queue[Path] = asyncio.Queue()
        self.debouncer: dict[Path, float] = {}
        self.debounce_seconds = 1.0

        # We monitor specific deployed paths directly to ensure we catch reads
        self.canary_paths = [
            path.resolve() for path in self.platform.get_target_canary_paths().values()
        ]
        # Also add any explicitly registered canaries from the registry
        for path in self.registry.get_all_paths():
            self.canary_paths.append(path.resolve())
        # Deduplicate
        self.canary_paths = list(set(self.canary_paths))
        self._atime_cache: dict[Path, float] = {}

    async def _poll_access(self) -> None:
        """Polls st_atime for true file access (zero-privilege)."""
        logger.debug(
            f"Monitor checking {len(self.canary_paths)} paths: {self.canary_paths}"
        )
        # Initialize atime cache
        for path in self.canary_paths:
            if path.exists():
                self._atime_cache[path] = os.stat(path).st_atime

        while True:
            for path in self.canary_paths:
                if not path.exists():
                    continue
                try:
                    current_atime = os.stat(path).st_atime
                    cached_atime = self._atime_cache.get(path)

                    if cached_atime is not None and current_atime > cached_atime:
                        logger.debug(
                            f"Atime change detected on {path}: "
                            f"{cached_atime} -> {current_atime}"
                        )
                        # Atime changed = file was read!
                        self._atime_cache[path] = current_atime
                        self.queue.put_nowait(path)
                    elif cached_atime is None:
                        self._atime_cache[path] = current_atime
                except OSError:
                    pass
            # 10ms polling for sub-30ms detection latency
            await asyncio.sleep(0.01)

    async def _process_events(
        self, mitigator_callback: Callable[[int, Path], Coroutine[Any, Any, None]]
    ) -> None:
        while True:
            full_path = await self.queue.get()

            # Check debouncer
            now = time.time()
            last_seen = self.debouncer.get(full_path, 0.0)
            if now - last_seen < self.debounce_seconds:
                self.queue.task_done()
                continue

            self.debouncer[full_path] = now

            # We defer to the mitigator logic securely
            triggering_pid = self.platform.find_pid_accessing_file(full_path)
            if triggering_pid:
                # Dispatch asynchronously so we don't block processing other events
                asyncio.create_task(mitigator_callback(triggering_pid, full_path))
            else:
                logger.warning(f"Could not attribute PID for read on {full_path}")

            self.queue.task_done()

    async def start(
        self, mitigator_callback: Callable[[int, Path], Coroutine[Any, Any, None]]
    ) -> None:
        """Start the async polling loop to monitor read-access events."""
        logger.info("Starting read-access monitor on deployed canaries.")

        poll_task = asyncio.create_task(self._poll_access())
        process_task = asyncio.create_task(self._process_events(mitigator_callback))

        try:
            await asyncio.gather(poll_task, process_task)
        except asyncio.CancelledError:
            poll_task.cancel()
            process_task.cancel()
