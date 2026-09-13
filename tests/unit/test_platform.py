from unittest.mock import MagicMock, patch

import pytest

from deceptenv.exceptions import ProcessOwnershipViolation
from deceptenv.platform.darwin import DarwinAdapter
from deceptenv.platform.linux import LinuxAdapter
from deceptenv.platform.windows import WindowsAdapter


def test_linux_adapter_freeze_ownership_violation():
    adapter = LinuxAdapter()
    
    with patch("os.getuid", return_value=1000):
        with patch.object(adapter, "get_process_owner", return_value=2000):
            with pytest.raises(ProcessOwnershipViolation) as exc:
                adapter.freeze_pid(1234)
            
            assert "PID 1234 is owned by UID 2000, not 1000." in str(exc.value)

def test_linux_adapter_freeze_ownership_success():
    adapter = LinuxAdapter()
    
    with patch("os.getuid", return_value=1000):
        with patch.object(adapter, "get_process_owner", return_value=1000):
            with patch("os.kill") as mock_kill:
                adapter.freeze_pid(1234)
                mock_kill.assert_called_once()


def test_darwin_adapter_freeze_ownership_violation():
    adapter = DarwinAdapter()
    
    with patch("os.getuid", return_value=501):
        with patch.object(adapter, "get_process_owner", return_value=0):
            with pytest.raises(ProcessOwnershipViolation) as exc:
                adapter.freeze_pid(1234)
            
            assert "PID 1234 is owned by UID 0, not 501." in str(exc.value)


def test_windows_adapter_freeze_ownership_violation():
    adapter = WindowsAdapter()
    
    with patch("deceptenv.platform.windows.ntdll", MagicMock()):
        with patch("deceptenv.platform.windows.kernel32", MagicMock()):
            with patch.object(adapter, "_get_current_user_sid", return_value="S-1-5-21-XXX"):
                with patch.object(adapter, "get_process_owner", return_value="S-1-5-18"):
                    with pytest.raises(ProcessOwnershipViolation) as exc:
                        adapter.freeze_pid(1234)
                    
                    assert "PID 1234 is owned by SID S-1-5-18, not S-1-5-21-XXX." in str(exc.value)
