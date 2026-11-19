import json
import logging
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)


class SecurityConfig(BaseModel):
    """
    Immutable configuration for the core engine.
    Utilizes Pydantic to enforce type safety and frozen instances.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    canary_directory: Path = Field(
        ..., description="The base directory where tripwires will be deployed."
    )
    max_forensic_dump_size_bytes: int = Field(
        default=2 * 1024 * 1024,  # 2MB max
        ge=1,
        le=2 * 1024 * 1024,
        description="Maximum size in bytes for memory dumping to prevent DoS (max 2MB).",
    )
    mitigation_enabled: bool = Field(
        default=True,
        description="Whether to actively suspend processes that touch canaries.",
    )
    log_threshold: str = Field(
        default="WARNING", description="Logging threshold for the security engine."
    )
    slack_webhook_url: Optional[str] = Field(
        default=None,
        description="Optional webhook URL to dispatch forensic reports to.",
    )
    dashboard_auth_token: Optional[str] = Field(
        default=None,
        description="Bearer token for authenticating web dashboard API requests.",
    )

    @field_validator("canary_directory")
    @classmethod
    def resolve_and_secure_path(cls, v: Path) -> Path:
        """
        Enforce absolute paths and prevent directory traversal.
        """
        resolved = v.resolve()

        # Comprehensive deny-list of sensitive system directories
        forbidden_roots = {
            Path("/"), Path("/bin"), Path("/sbin"), Path("/etc"),
            Path("/usr"), Path("/var"), Path("/System"), Path("/Library"),
            Path("/boot"), Path("/dev"), Path("/proc"), Path("/sys"),
        }
        if resolved in forbidden_roots:
            raise ValueError(
                f"Cannot use {resolved} as a canary directory for security."
            )

        return resolved

    @field_validator("slack_webhook_url")
    @classmethod
    def validate_webhook_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate that the Slack webhook URL is well-formed."""
        if v is None:
            return v
        if not v.startswith("https://"):
            raise ValueError("Slack webhook URL must use HTTPS.")
        return v


def load_config() -> SecurityConfig:
    """
    Load configuration from multiple sources with priority:
    1. Config file (~/.config/deceptenv/config.json or ./deceptenv.json)
    2. Environment variables
    3. Defaults
    """
    config_search_paths = [
        Path.home() / ".config" / "deceptenv" / "config.json",
        Path(os.getcwd()) / "deceptenv.json",
        Path(os.getcwd()) / ".deceptenv.json",
    ]

    file_config: dict = {}

    for config_path in config_search_paths:
        if config_path.exists() and config_path.is_file():
            try:
                with open(config_path, "r") as f:
                    file_config = json.load(f)
                logger.info(f"Loaded configuration from {config_path}")
                break
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to parse config file {config_path}: {e}")

    # Environment variables override file config
    canary_dir = os.environ.get(
        "DECEPTENV_CANARY_DIR",
        file_config.get(
            "canary_directory",
            str(Path(os.getcwd()) / ".deceptenv_canaries"),
        ),
    )

    slack_url = os.environ.get(
        "SLACK_WEBHOOK_URL",
        file_config.get("slack_webhook_url"),
    )

    auth_token = os.environ.get(
        "DECEPTENV_DASHBOARD_TOKEN",
        file_config.get("dashboard_auth_token"),
    )

    return SecurityConfig(
        canary_directory=Path(canary_dir),
        slack_webhook_url=slack_url,
        dashboard_auth_token=auth_token,
        max_forensic_dump_size_bytes=int(
            file_config.get("max_forensic_dump_size_bytes", 2 * 1024 * 1024)
        ),
        mitigation_enabled=bool(
            file_config.get("mitigation_enabled", True)
        ),
        log_threshold=str(
            file_config.get("log_threshold", "WARNING")
        ),
    )
