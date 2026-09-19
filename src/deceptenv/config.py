from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


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

    @field_validator("canary_directory")
    @classmethod
    def resolve_and_secure_path(cls, v: Path) -> Path:
        """
        Enforce absolute paths and prevent directory traversal.
        """
        resolved = v.resolve()

        # Ensure it doesn't resolve to sensitive root directories unexpectedly
        forbidden_roots = {Path("/"), Path("/bin"), Path("/sbin"), Path("/etc")}
        if resolved in forbidden_roots:
            raise ValueError(
                f"Cannot use {resolved} as a canary directory for security."
            )

        return resolved


def load_config() -> SecurityConfig:
    """
    Stub for loading configuration from a secure source.
    """
    import os

    return SecurityConfig(
        canary_directory=Path(os.getcwd()) / ".deceptenv_canaries",
        slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL"),
    )
