from __future__ import annotations

import logging
import os
import signal
from pathlib import Path

import psutil

from deceptenv.config import load_config
from deceptenv.exceptions import OSPrimitiveError, ProcessOwnershipViolation

from .base import PlatformAdapter

logger = logging.getLogger(__name__)


class DarwinAdapter(PlatformAdapter):
    """macOS specific OS primitives using psutil."""

    def get_target_canary_paths(self) -> dict[str, Path]:
        config = load_config()
        return {
            "dummy_file": config.canary_directory / "passwords.txt",
            "dummy_db": config.canary_directory / "wallet.dat",
        }

    def get_process_owner(self, pid: int) -> int | str:
        try:
            p = psutil.Process(pid)
            return p.uids().real
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return -1

    def find_pid_accessing_file(self, file_path: Path) -> int | None:
        current_uid = os.getuid()
        target_str = str(file_path.resolve())

        for p in psutil.process_iter(["pid", "uids"]):
            try:
                # Type ignoring because psutil type stubs can be imprecise for info dicts
                uids = p.info.get("uids") # type: ignore
                pid = p.info.get("pid") # type: ignore
                
                if not uids or not pid:
                    continue
                    
                if uids.real != current_uid:
                    continue

                for f in p.open_files():
                    if f.path == target_str:
                        return pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass
        return None

    def _verify_ownership(self, pid: int) -> None:
        current_uid = os.getuid()
        owner = self.get_process_owner(pid)
        if owner != current_uid:
            raise ProcessOwnershipViolation(
                f"PID {pid} is owned by UID {owner}, not {current_uid}."
            )

    def freeze_pid(self, pid: int) -> bool:
        self._verify_ownership(pid)
        try:
            os.kill(pid, signal.SIGSTOP)
            return True
        except ProcessLookupError:
            return False
        except PermissionError as e:
            raise OSPrimitiveError(f"Permission denied: {pid}") from e

    def resume_pid(self, pid: int) -> bool:
        self._verify_ownership(pid)
        try:
            os.kill(pid, signal.SIGCONT)
            return True
        except ProcessLookupError:
            return False
        except PermissionError as e:
            raise OSPrimitiveError(f"Permission denied: {pid}") from e
