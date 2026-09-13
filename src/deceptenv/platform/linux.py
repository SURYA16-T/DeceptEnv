from __future__ import annotations

import logging
import os
import signal
from pathlib import Path

from deceptenv.config import load_config
from deceptenv.exceptions import OSPrimitiveError, ProcessOwnershipViolation

from .base import PlatformAdapter

logger = logging.getLogger(__name__)


class LinuxAdapter(PlatformAdapter):
    """Linux specific OS primitives."""

    def get_target_canary_paths(self) -> dict[str, Path]:
        config = load_config()
        # Stub logic to return dummy canaries for monitoring
        return {
            "dummy_file": config.canary_directory / "passwords.txt",
            "dummy_db": config.canary_directory / "wallet.dat",
        }

    def get_process_owner(self, pid: int) -> int | str:
        """Parse /proc/[pid]/status for Uid."""
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        parts = line.split()
                        if len(parts) > 1:
                            return int(parts[1])
        except (FileNotFoundError, PermissionError, ValueError) as e:
            logger.debug(f"Failed to read owner for PID {pid}: {e}")
            return -1
        return -1

    def find_pid_accessing_file(self, file_path: Path) -> int | None:
        """Iterate /proc/*/fd/* checking only our own processes."""
        current_uid = os.getuid()
        target_str = str(file_path.resolve())

        try:
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)

                # Skip PIDs we don't own to avoid permission errors
                if self.get_process_owner(pid) != current_uid:
                    continue

                fd_dir = f"/proc/{pid}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        fd_path = os.path.join(fd_dir, fd)
                        try:
                            target = os.readlink(fd_path)
                            if target == target_str:
                                return pid
                        except (FileNotFoundError, OSError):
                            pass
                except (FileNotFoundError, PermissionError):
                    pass
        except OSError as e:
            logger.debug(f"Error traversing /proc: {e}")

        return None

    def _verify_ownership(self, pid: int) -> None:
        current_uid = os.getuid()
        owner = self.get_process_owner(pid)
        if owner != current_uid:
            raise ProcessOwnershipViolation(
                f"PID {pid} is owned by UID {owner}, not {current_uid}."
            )

    def freeze_pid(self, pid: int) -> bool:
        """Send SIGSTOP using os.kill with UID checking."""
        self._verify_ownership(pid)
        try:
            os.kill(pid, signal.SIGSTOP)
            return True
        except ProcessLookupError:
            return False
        except PermissionError as e:
            raise OSPrimitiveError(f"Permission denied: {pid}") from e

    def resume_pid(self, pid: int) -> bool:
        """Send SIGCONT using os.kill with UID checking."""
        self._verify_ownership(pid)
        try:
            os.kill(pid, signal.SIGCONT)
            return True
        except ProcessLookupError:
            return False
        except PermissionError as e:
            raise OSPrimitiveError(f"Permission denied: {pid}") from e
