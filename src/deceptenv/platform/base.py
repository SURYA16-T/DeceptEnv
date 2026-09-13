from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class PlatformAdapter(ABC):
    """Abstract Base Class defining secure OS primitives."""
    
    @abstractmethod
    def get_target_canary_paths(self) -> dict[str, Path]:
        """Return a mapping of canary identifiers to their deployed Paths."""
        pass

    @abstractmethod
    def find_pid_accessing_file(self, file_path: Path) -> int | None:
        """Find the PID of a process accessing the given file path."""
        pass

    @abstractmethod
    def freeze_pid(self, pid: int) -> bool:
        """Safely suspend a process ensuring it belongs to the current user."""
        pass

    @abstractmethod
    def resume_pid(self, pid: int) -> bool:
        """Safely resume a process ensuring it belongs to the current user."""
        pass

    def get_process_lineage(self, pid: int) -> list[int]:
        """Get the process tree lineage of a given PID."""
        import psutil
        lineage = []
        try:
            proc = psutil.Process(pid)
            while proc.parent():
                proc = proc.parent()
                if proc:
                    lineage.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return lineage

    @abstractmethod
    def get_process_owner(self, pid: int) -> int | str:
        """Retrieve the UID or SID of the process."""
        pass
