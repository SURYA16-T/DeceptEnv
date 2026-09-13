from __future__ import annotations

import ctypes
import logging
import platform
from ctypes import wintypes
from pathlib import Path

from deceptenv.config import load_config
from deceptenv.exceptions import ProcessOwnershipViolation

from .base import PlatformAdapter

logger = logging.getLogger(__name__)

if platform.system() == "Windows":
    rstrtmgr = ctypes.windll.Rstrtmgr  # type: ignore
    kernel32 = ctypes.windll.kernel32  # type: ignore
    advapi32 = ctypes.windll.advapi32  # type: ignore
    ntdll = ctypes.windll.ntdll  # type: ignore
else:
    rstrtmgr = None
    kernel32 = None
    advapi32 = None
    ntdll = None

# Windows Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
TOKEN_QUERY = 0x0008
TokenUser = 1
ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),
    ]


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", wintypes.FILETIME),
    ]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * 256),
        ("strServiceShortName", wintypes.WCHAR * 64),
        ("ApplicationType", wintypes.DWORD),
        ("AppStatus", wintypes.DWORD),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


class WindowsAdapter(PlatformAdapter):
    """Windows specific OS primitives."""

    def get_target_canary_paths(self) -> dict[str, Path]:
        config = load_config()
        return {
            "dummy_file": config.canary_directory / "passwords.txt",
            "dummy_db": config.canary_directory / "wallet.dat",
        }

    def _get_current_user_sid(self) -> str:
        if kernel32 and advapi32:
            return str(self.get_process_owner(kernel32.GetCurrentProcessId()))
        return ""

    def get_process_owner(self, pid: int) -> int | str:
        if not kernel32 or not advapi32:
            return ""

        hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not hProcess:
            return ""

        hToken = wintypes.HANDLE()
        try:
            if not advapi32.OpenProcessToken(
                hProcess, TOKEN_QUERY, ctypes.byref(hToken)
            ):
                return ""

            cbSize = wintypes.DWORD(0)
            advapi32.GetTokenInformation(hToken, TokenUser, None, 0, ctypes.byref(cbSize))

            if cbSize.value == 0:
                return ""

            TokenInformation = ctypes.create_string_buffer(cbSize.value)
            if not advapi32.GetTokenInformation(
                hToken, TokenUser, TokenInformation, cbSize, ctypes.byref(cbSize)
            ):
                return ""

            token_user = ctypes.cast(
                TokenInformation, ctypes.POINTER(TOKEN_USER)
            ).contents
            sid_str_ptr = ctypes.c_wchar_p()
            
            if advapi32.ConvertSidToStringSidW(token_user.User.Sid, ctypes.byref(sid_str_ptr)):
                sid = sid_str_ptr.value
                kernel32.LocalFree(sid_str_ptr)
                return str(sid)
        finally:
            if hToken:
                kernel32.CloseHandle(hToken)
            kernel32.CloseHandle(hProcess)

        return ""

    def find_pid_accessing_file(self, file_path: Path) -> int | None:
        if not rstrtmgr:
            return None

        session_handle = wintypes.DWORD(0)
        session_key = (wintypes.WCHAR * 33)()

        err = rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key)
        if err != ERROR_SUCCESS:
            return None

        try:
            target_str = str(file_path.resolve())
            files = (ctypes.c_wchar_p * 1)(target_str)

            err = rstrtmgr.RmRegisterResources(
                session_handle, 1, files, 0, None, 0, None
            )
            if err != ERROR_SUCCESS:
                return None

            nProcInfoNeeded = wintypes.DWORD(0)
            nProcInfo = wintypes.DWORD(0)
            dwReason = wintypes.DWORD(0)

            err = rstrtmgr.RmGetList(
                session_handle,
                ctypes.byref(nProcInfoNeeded),
                ctypes.byref(nProcInfo),
                None,
                ctypes.byref(dwReason),
            )

            if err == ERROR_MORE_DATA or err == ERROR_SUCCESS:
                if nProcInfoNeeded.value > 0:
                    process_info_array = (RM_PROCESS_INFO * nProcInfoNeeded.value)()
                    nProcInfo.value = nProcInfoNeeded.value

                    err = rstrtmgr.RmGetList(
                        session_handle,
                        ctypes.byref(nProcInfoNeeded),
                        ctypes.byref(nProcInfo),
                        process_info_array,
                        ctypes.byref(dwReason),
                    )

                    if err == ERROR_SUCCESS and nProcInfo.value > 0:
                        pid = process_info_array[0].Process.dwProcessId
                        current_sid = self._get_current_user_sid()
                        if self.get_process_owner(int(pid)) == current_sid:
                            return int(pid)
        finally:
            rstrtmgr.RmEndSession(session_handle)

        # TIER 2: Heuristic Fallback for short-lived access
        import time
        import psutil
        best_pid = None
        highest_time = 0.0
        current_time = time.time()
        
        current_sid = self._get_current_user_sid()
        for p in psutil.process_iter(['pid', 'create_time']):
            try:
                pid = p.info.get('pid') # type: ignore
                create_time = p.info.get('create_time') # type: ignore
                
                if not pid or not create_time:
                    continue
                    
                if self.get_process_owner(int(pid)) == current_sid and pid != __import__("os").getpid():
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
        current_sid = self._get_current_user_sid()
        owner = self.get_process_owner(pid)
        if owner != current_sid:
            raise ProcessOwnershipViolation(
                f"PID {pid} is owned by SID {owner}, not {current_sid}."
            )

    def freeze_pid(self, pid: int) -> bool:
        if not ntdll or not kernel32:
            return False

        self._verify_ownership(pid)

        hProcess = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not hProcess:
            return False

        try:
            status = ntdll.NtSuspendProcess(hProcess)
            return status == 0
        finally:
            kernel32.CloseHandle(hProcess)

    def resume_pid(self, pid: int) -> bool:
        if not ntdll or not kernel32:
            return False

        self._verify_ownership(pid)

        hProcess = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not hProcess:
            return False

        try:
            status = ntdll.NtResumeProcess(hProcess)
            return status == 0
        finally:
            kernel32.CloseHandle(hProcess)
