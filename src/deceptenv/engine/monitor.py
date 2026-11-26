import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Coroutine, Tuple

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
        canary_set: set[Path] = {
            path.resolve() for path in self.platform.get_target_canary_paths().values()
        }
        canary_set.update(path.resolve() for path in self.registry.get_all_paths())
        self.canary_paths = list(canary_set)
        self._stat_cache: dict[Path, Tuple[int, int]] = {}
        self._active_tasks: set[asyncio.Task[None]] = set()

    def _sync_registered_paths(self) -> None:
        """Include any newly registered canaries without dropping existing targets."""
        known = set(self.canary_paths)
        for path in self.registry.get_all_paths():
            resolved = path.resolve()
            if resolved not in known:
                known.add(resolved)
                self.canary_paths.append(resolved)

    @staticmethod
    def _arm_path(path: Path) -> Tuple[int, int]:
        """Ensure st_atime < st_mtime so APFS/relatime updates st_atime on subsequent reads."""
        st = os.stat(path)
        if st.st_atime_ns >= st.st_mtime_ns:
            os.utime(path, (st.st_mtime - 10.0, st.st_mtime))
            st = os.stat(path)
        return (st.st_atime_ns, st.st_mtime_ns)

    async def _poll_access(self) -> None:
        """Polls st_atime_ns and st_mtime_ns for zero-privilege read/tamper detection."""
        self._sync_registered_paths()
        logger.debug(
            f"Monitor checking {len(self.canary_paths)} paths: {self.canary_paths}"
        )
        # Arm existing canaries so st_atime < st_mtime on startup
        for path in self.canary_paths:
            try:
                if path.exists():
                    self._stat_cache[path] = self._arm_path(path)
            except OSError:
                pass

        while True:
            self._sync_registered_paths()
            for path in self.canary_paths:
                try:
                    if not path.exists():
                        continue
                    st = os.stat(path)
                    current_atime = st.st_atime_ns
                    current_mtime = st.st_mtime_ns
                    cached = self._stat_cache.get(path)

                    if cached is not None:
                        cached_atime, cached_mtime = cached
                        if current_atime > cached_atime or current_mtime != cached_mtime:
                            logger.debug(
                                f"Access/modification detected on {path}: "
                                f"atime {cached_atime}->{current_atime}, "
                                f"mtime {cached_mtime}->{current_mtime}"
                            )
                            # Re-arm immediately so future natural reads also update st_atime_ns
                            self._stat_cache[path] = self._arm_path(path)
                            self.queue.put_nowait(path)
                    else:
                        self._stat_cache[path] = self._arm_path(path)
                except OSError:
                    pass
            # 10ms polling for sub-30ms detection latency
            await asyncio.sleep(0.01)

    def _on_mitigation_done(self, task: asyncio.Task[None]) -> None:
        self._active_tasks.discard(task)
        if not task.cancelled():
            exc = task.exception()
            if exc is not None:
                logger.error(f"Mitigation callback failed: {exc}")

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
                # Dispatch asynchronously with tracked reference to prevent GC & capture errors
                task = asyncio.create_task(mitigator_callback(triggering_pid, full_path))
                self._active_tasks.add(task)
                task.add_done_callback(self._on_mitigation_done)
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
            for task in list(self._active_tasks):
                task.cancel()
            await asyncio.gather(
                poll_task, process_task, *self._active_tasks, return_exceptions=True
            )
