from unittest.mock import MagicMock, patch

import pytest

from deceptenv.exceptions import ProcessOwnershipViolation
from deceptenv.platform.darwin import DarwinAdapter
from deceptenv.platform.linux import LinuxAdapter
from deceptenv.platform.windows import WindowsAdapter


def test_linux_adapter_freeze_ownership_violation() -> None:
    adapter = LinuxAdapter()

    with patch("os.getuid", return_value=1000):
        with patch.object(adapter, "get_process_owner", return_value=2000):
            with pytest.raises(ProcessOwnershipViolation) as exc:
                adapter.freeze_pid(1234)

            assert "PID 1234 is owned by UID 2000, not 1000." in str(exc.value)


def test_linux_adapter_freeze_ownership_success() -> None:
    adapter = LinuxAdapter()

    with patch("os.getuid", return_value=1000):
        with patch.object(adapter, "get_process_owner", return_value=1000):
            with patch("os.kill") as mock_kill:
                adapter.freeze_pid(1234)
                mock_kill.assert_called_once()


def test_darwin_adapter_freeze_ownership_violation() -> None:
    adapter = DarwinAdapter()

    with patch("os.getuid", return_value=501):
        with patch.object(adapter, "get_process_owner", return_value=0):
            with pytest.raises(ProcessOwnershipViolation) as exc:
                adapter.freeze_pid(1234)

            assert "PID 1234 is owned by UID 0, not 501." in str(exc.value)


def test_darwin_adapter_freeze_ownership_success() -> None:
    adapter = DarwinAdapter()

    with patch("os.getuid", return_value=501):
        with patch.object(adapter, "get_process_owner", return_value=501):
            with patch("os.kill") as mock_kill:
                assert adapter.freeze_pid(1234) is True
                mock_kill.assert_called_once()


def test_darwin_adapter_resume_success() -> None:
    adapter = DarwinAdapter()

    with patch("os.getuid", return_value=501):
        with patch.object(adapter, "get_process_owner", return_value=501):
            with patch("os.kill") as mock_kill:
                assert adapter.resume_pid(1234) is True
                mock_kill.assert_called_once()


def test_windows_adapter_freeze_ownership_violation() -> None:
    adapter = WindowsAdapter()

    with patch("deceptenv.platform.windows.ntdll", MagicMock()):
        with patch("deceptenv.platform.windows.kernel32", MagicMock()):
            with patch.object(
                adapter, "_get_current_user_sid", return_value="S-1-5-21-XXX"
            ):
                with patch.object(
                    adapter, "get_process_owner", return_value="S-1-5-18"
                ):
                    with pytest.raises(ProcessOwnershipViolation) as exc:
                        adapter.freeze_pid(1234)

                    assert (
                        "PID 1234 is owned by SID S-1-5-18, not S-1-5-21-XXX."
                        in str(exc.value)
                    )


def test_windows_adapter_freeze_ownership_success() -> None:
    adapter = WindowsAdapter()
    mock_ntdll = MagicMock()
    mock_ntdll.NtSuspendProcess.return_value = 0
    mock_kernel32 = MagicMock()
    mock_kernel32.OpenProcess.return_value = 9999

    with patch("deceptenv.platform.windows.ntdll", mock_ntdll):
        with patch("deceptenv.platform.windows.kernel32", mock_kernel32):
            with patch.object(
                adapter, "_get_current_user_sid", return_value="S-1-5-21-XXX"
            ):
                with patch.object(
                    adapter, "get_process_owner", return_value="S-1-5-21-XXX"
                ):
                    assert adapter.freeze_pid(1234) is True
                    mock_ntdll.NtSuspendProcess.assert_called_once_with(9999)
                    mock_kernel32.CloseHandle.assert_called_once_with(9999)


def test_windows_adapter_resume_ownership_success() -> None:
    adapter = WindowsAdapter()
    mock_ntdll = MagicMock()
    mock_ntdll.NtResumeProcess.return_value = 0
    mock_kernel32 = MagicMock()
    mock_kernel32.OpenProcess.return_value = 9999

    with patch("deceptenv.platform.windows.ntdll", mock_ntdll):
        with patch("deceptenv.platform.windows.kernel32", mock_kernel32):
            with patch.object(
                adapter, "_get_current_user_sid", return_value="S-1-5-21-XXX"
            ):
                with patch.object(
                    adapter, "get_process_owner", return_value="S-1-5-21-XXX"
                ):
                    assert adapter.resume_pid(1234) is True
                    mock_ntdll.NtResumeProcess.assert_called_once_with(9999)
                    mock_kernel32.CloseHandle.assert_called_once_with(9999)


def test_get_platform_adapter_factory() -> None:
    from deceptenv.exceptions import PlatformNotSupportedError
    from deceptenv.platform import get_platform_adapter

    with patch("sys.platform", "linux"):
        assert isinstance(get_platform_adapter(), LinuxAdapter)

    with patch("sys.platform", "darwin"):
        assert isinstance(get_platform_adapter(), DarwinAdapter)

    with patch("sys.platform", "win32"):
        assert isinstance(get_platform_adapter(), WindowsAdapter)

    with patch("sys.platform", "freebsd"):
        with pytest.raises(PlatformNotSupportedError):
            get_platform_adapter()


def test_canary_paths_contract_across_all_adapters() -> None:
    for adapter in [LinuxAdapter(), DarwinAdapter(), WindowsAdapter()]:
        paths = adapter.get_target_canary_paths()
        assert "aws_credentials" in paths
        assert "chrome_cookies" in paths
        assert "system_config" in paths
        assert "env_file" in paths

