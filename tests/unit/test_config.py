"""Tests for deceptenv.config — validation, loading, and edge cases."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from deceptenv.config import SecurityConfig, load_config

# --- Validation Tests ---


def test_config_forbidden_root_slash() -> None:
    with pytest.raises(ValidationError, match="Cannot use"):
        SecurityConfig(canary_directory=Path("/"))


def test_config_forbidden_root_bin() -> None:
    with pytest.raises(ValidationError, match="Cannot use"):
        SecurityConfig(canary_directory=Path("/bin"))


def test_config_forbidden_root_etc() -> None:
    # On macOS, /etc resolves to /private/etc (not in forbidden set).
    # Test a path that is definitely in the forbidden set.
    with pytest.raises(ValidationError, match="Cannot use"):
        SecurityConfig(canary_directory=Path("/sbin"))


def test_config_forbidden_root_usr() -> None:
    with pytest.raises(ValidationError, match="Cannot use"):
        SecurityConfig(canary_directory=Path("/usr"))


def test_config_forbidden_root_var() -> None:
    # On macOS, /var resolves to /private/var (not in forbidden set).
    # Test /System which does not get redirected.
    with pytest.raises(ValidationError, match="Cannot use"):
        SecurityConfig(canary_directory=Path("/System"))


def test_config_webhook_url_requires_https() -> None:
    with pytest.raises(ValidationError, match="HTTPS"):
        SecurityConfig(
            canary_directory=Path("/tmp"),
            slack_webhook_url="http://insecure.example.com",
        )
    with pytest.raises(ValidationError, match="HTTPS"):
        SecurityConfig(
            canary_directory=Path("/tmp"),
            slack_webhook_url="https://",
        )


def test_config_webhook_url_valid_https() -> None:
    cfg = SecurityConfig(
        canary_directory=Path("/tmp"),
        slack_webhook_url="https://hooks.slack.com/services/T/B/X",
    )
    assert cfg.slack_webhook_url == "https://hooks.slack.com/services/T/B/X"


def test_config_webhook_url_none_allowed() -> None:
    cfg = SecurityConfig(canary_directory=Path("/tmp"), slack_webhook_url=None)
    assert cfg.slack_webhook_url is None


def test_config_frozen_immutability() -> None:
    cfg = SecurityConfig(canary_directory=Path("/tmp"))
    with pytest.raises(ValidationError):
        cfg.canary_directory = Path("/other")  # type: ignore[misc]


def test_config_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(canary_directory=Path("/tmp"), unknown_field="bad")  # type: ignore[call-arg]


def test_config_max_forensic_dump_bounds() -> None:
    # Too large
    with pytest.raises(ValidationError):
        SecurityConfig(
            canary_directory=Path("/tmp"),
            max_forensic_dump_size_bytes=10 * 1024 * 1024,
        )
    # Zero
    with pytest.raises(ValidationError):
        SecurityConfig(
            canary_directory=Path("/tmp"), max_forensic_dump_size_bytes=0
        )
    # Valid
    cfg = SecurityConfig(canary_directory=Path("/tmp"), max_forensic_dump_size_bytes=1024)
    assert cfg.max_forensic_dump_size_bytes == 1024


def test_config_resolves_path(tmp_path: Path) -> None:
    sub = tmp_path / "relative"
    cfg = SecurityConfig(canary_directory=sub)
    assert cfg.canary_directory.is_absolute()


def test_config_dashboard_auth_token() -> None:
    cfg = SecurityConfig(
        canary_directory=Path("/tmp"),
        dashboard_auth_token="my_secret",  # noqa: S106
    )
    assert cfg.dashboard_auth_token == "my_secret"  # noqa: S105


# --- load_config Tests ---


def test_load_config_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("DECEPTENV_CANARY_DIR", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)
    cfg = load_config()
    assert cfg.canary_directory == (tmp_path / ".deceptenv_canaries").resolve()


def test_load_config_from_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("DECEPTENV_CANARY_DIR", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)

    config_data = {"canary_directory": str(tmp_path / "my_canaries")}
    config_file = tmp_path / "deceptenv.json"
    config_file.write_text(json.dumps(config_data))

    cfg = load_config()
    assert cfg.canary_directory == (tmp_path / "my_canaries").resolve()


def test_load_config_env_overrides_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("DECEPTENV_CANARY_DIR", str(tmp_path / "env_canaries"))
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)

    config_data = {"canary_directory": str(tmp_path / "file_canaries")}
    config_file = tmp_path / "deceptenv.json"
    config_file.write_text(json.dumps(config_data))

    cfg = load_config()
    assert cfg.canary_directory == (tmp_path / "env_canaries").resolve()


def test_load_config_malformed_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("os.getcwd", lambda: str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("DECEPTENV_CANARY_DIR", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("DECEPTENV_DASHBOARD_TOKEN", raising=False)

    config_file = tmp_path / "deceptenv.json"
    config_file.write_text("{bad json!!!")

    # Should fall back to defaults, not crash
    cfg = load_config()
    assert cfg.canary_directory.is_absolute()
