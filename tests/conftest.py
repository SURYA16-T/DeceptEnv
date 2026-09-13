from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def mock_canary_dir(tmp_path: Path) -> Path:
    """Provides a safe, isolated directory for canary tests."""
    canary_dir = tmp_path / ".deceptenv_test_canaries"
    canary_dir.mkdir()
    return canary_dir

@pytest.fixture
def mock_platform_adapter(mocker: Any) -> Any:
    """Mocks the platform adapter to prevent tests from executing real OS primitives."""
    # This assumes tests will use pytest-mock
    mock_adapter = mocker.MagicMock()
    mock_adapter.suspend_process.return_value = True
    return mock_adapter
