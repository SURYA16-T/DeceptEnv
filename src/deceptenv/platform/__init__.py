import sys

from .base import PlatformAdapter


def get_platform_adapter() -> PlatformAdapter:
    """Factory method to get the correct adapter for the current OS."""
    if sys.platform == "linux":
        from .linux import LinuxAdapter
        return LinuxAdapter()
    elif sys.platform == "darwin":
        from .darwin import DarwinAdapter
        return DarwinAdapter()
    elif sys.platform == "win32":
        from .windows import WindowsAdapter
        return WindowsAdapter()
    else:
        from deceptenv.exceptions import PlatformNotSupportedError
        raise PlatformNotSupportedError(f"Unsupported OS: {sys.platform}")
