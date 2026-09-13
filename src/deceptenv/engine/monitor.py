import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Coroutine

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from deceptenv.canary.registry import CanaryRegistry
from deceptenv.platform import get_platform_adapter

logger = logging.getLogger(__name__)

class CanaryEventHandler(FileSystemEventHandler):
    def __init__(self, queue: asyncio.Queue[Path]) -> None:
        super().__init__()
        self.queue = queue
        self.loop = asyncio.get_running_loop()

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, Path(os.fsdecode(event.src_path)))

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, Path(os.fsdecode(event.src_path)))

class CanaryMonitor:
    """High-throughput async filesystem event loop for tripwire monitoring."""
    
    def __init__(self, directory: Path, registry: CanaryRegistry) -> None:
        self.directory = directory
        self.registry = registry
        self.platform = get_platform_adapter()
        self.queue: asyncio.Queue[Path] = asyncio.Queue()
        self.debouncer: dict[Path, float] = {}
        self.debounce_seconds = 1.0
        
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
            
            # Resolve canonical
            full_path = full_path.resolve()
            
            if self.registry.is_canary(full_path):
                # We defer to the mitigator logic securely
                triggering_pid = self.platform.find_pid_accessing_file(full_path)
                if triggering_pid:
                    # Dispatch asynchronously so we don't block processing other events
                    asyncio.create_task(mitigator_callback(triggering_pid, full_path))
                    
            self.queue.task_done()

    async def start(
        self, mitigator_callback: Callable[[int, Path], Coroutine[Any, Any, None]]
    ) -> None:
        """Start the async event loop to monitor filesystem events."""
        logger.info(f"Starting monitor on {self.directory}")
        
        event_handler = CanaryEventHandler(self.queue)
        observer = Observer()
        observer.schedule(event_handler, str(self.directory), recursive=True)
        observer.start()
        
        try:
            await self._process_events(mitigator_callback)
        finally:
            observer.stop()
            observer.join()
