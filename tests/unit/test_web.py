"""Tests for deceptenv.web — REST API endpoints and dashboard handler."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

# ---------------------------------------------------------------------------
# Lightweight HTTP test helpers — no real sockets needed
# ---------------------------------------------------------------------------


def _make_handler(
    method: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    """Create a DashboardHandler wired to in-memory buffers."""
    from deceptenv.web import DashboardHandler

    handler = DashboardHandler.__new__(DashboardHandler)
    handler.path = path
    handler.command = method

    # Wire wfile to a BytesIO so we can read the response
    handler.wfile = BytesIO()
    handler.rfile = BytesIO()

    # Build a minimal headers object
    from http.client import HTTPMessage

    msg = HTTPMessage()
    for k, v in (headers or {}).items():
        msg[k] = v
    handler.headers = msg

    # Stub log and response-sending internals
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.client_address = ("127.0.0.1", 9999)
    handler.request_version = "HTTP/1.1"
    handler._headers_buffer: list[bytes] = []

    return handler


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDashboardAuth:
    """S2: dashboard_auth_token enforcement."""

    def test_api_open_when_no_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.delenv("DECEPTENV_CANARY_DIR", raising=False)
        monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

        import deceptenv.web as web_mod

        monkeypatch.setattr(web_mod, "_CACHED_CONFIG", None)

        handler = _make_handler("GET", "/api/canaries")
        assert handler._check_auth() is True

    def test_api_rejects_missing_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.delenv("DECEPTENV_CANARY_DIR", raising=False)
        monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

        import deceptenv.web as web_mod
        from deceptenv.config import SecurityConfig

        mock_config = SecurityConfig(
            canary_directory=tmp_path,
            dashboard_auth_token="secret123",  # noqa: S106
        )
        monkeypatch.setattr(web_mod, "_CACHED_CONFIG", mock_config)

        handler = _make_handler("GET", "/api/canaries")
        handler.send_response = lambda code: setattr(handler, "_test_status", code)
        handler.send_header = lambda k, v: None
        handler.end_headers = lambda: None

        assert handler._check_auth() is False

    def test_api_accepts_valid_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.delenv("DECEPTENV_CANARY_DIR", raising=False)
        monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

        import deceptenv.web as web_mod
        from deceptenv.config import SecurityConfig

        mock_config = SecurityConfig(
            canary_directory=tmp_path,
            dashboard_auth_token="secret123",  # noqa: S106
        )
        monkeypatch.setattr(web_mod, "_CACHED_CONFIG", mock_config)

        handler = _make_handler(
            "GET",
            "/api/canaries",
            headers={"Authorization": "Bearer secret123"},
        )
        assert handler._check_auth() is True


class TestGetCanaryList:
    """Test get_canary_list() with mocked platform adapter."""

    def test_returns_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.delenv("DECEPTENV_CANARY_DIR", raising=False)
        monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

        import deceptenv.web as web_mod

        monkeypatch.setattr(web_mod, "_CACHED_CONFIG", None)
        monkeypatch.setattr(web_mod, "_CACHED_ADAPTER", None)

        result = web_mod.get_canary_list()
        assert isinstance(result, list)
        for item in result:
            assert "id" in item
            assert "status" in item


class TestGetSystemMetrics:
    """Test get_system_metrics() returns expected structure."""

    def test_metrics_structure(self) -> None:
        from deceptenv.web import get_system_metrics

        metrics = get_system_metrics()
        assert "ram_mb" in metrics
        assert "cpu_percent" in metrics
        assert "uptime_seconds" in metrics
        assert isinstance(metrics["ram_mb"], float)


class TestStateMutation:
    """Test _STATE is properly locked and mutated."""

    def test_state_initial_values(self) -> None:
        from deceptenv.web import _STATE

        assert "events_processed" in _STATE
        assert "threats_neutralized" in _STATE
        assert "incidents" in _STATE
