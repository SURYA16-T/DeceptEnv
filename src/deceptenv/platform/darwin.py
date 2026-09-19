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
        from deceptenv.canary.deployer import CanaryDeployer

        config = load_config()
        return {
            "aws_credentials": CanaryDeployer.get_aws_credentials_path(),
            "chrome_cookies": CanaryDeployer.get_chrome_cookies_path(
                config.canary_directory
            ),
            "system_config": CanaryDeployer.get_system_config_path(),
            "env_file": CanaryDeployer.get_env_file_path(config.canary_directory),
        }

    def get_process_owner(self, pid: int) -> int | str:
        try:
            p = psutil.Process(pid)
            return p.uids().real
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return -1

    def find_pid_accessing_file(self, file_path: Path) -> int | None:
        import time

        current_uid = os.getuid()
        target_str = str(file_path.resolve())

        # TIER 1: Standard Descriptor Scanning
        for p in psutil.process_iter(["pid", "uids"]):
            try:
                # Type ignoring because psutil type stubs can be imprecise
                uids = p.info.get("uids")
                pid = int(p.info.get("pid") or 0)

                if not uids or not pid:
                    continue

                if uids.real != current_uid:
                    continue

                for f in p.open_files():
                    if f.path == target_str:
                        return pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass

        # TIER 2: Heuristic Fallback for short-lived access
        best_pid = None
        highest_time = 0.0
        current_time = time.time()
        for p in psutil.process_iter(["pid", "uids", "create_time"]):
            try:
                uids = p.info.get("uids")
                pid = int(p.info.get("pid") or 0)
                create_time = p.info.get("create_time")

                if not uids or not pid or not create_time:
                    continue

                if uids.real == current_uid and pid != os.getpid():
                    # If spawned within the last 5 seconds (fast-close evasion window)
                    if current_time - create_time < 5.0:
                        if create_time > highest_time:
                            highest_time = create_time
                            best_pid = pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass

        if best_pid:
            return best_pid

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
