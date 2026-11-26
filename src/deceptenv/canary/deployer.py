from __future__ import annotations

import hmac
import os
import secrets
import sqlite3
import sys
from pathlib import Path

from deceptenv.exceptions import SecurityBoundaryViolation


class CanaryDeployer:
    """Secure deployer for generating deceptive files and tokens."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir

    def generate_token(self) -> str:
        """Generate a cryptographically secure, randomized tripwire token."""
        return secrets.token_hex(32)

    @staticmethod
    def _can_use_directory(target_dir: Path) -> bool:
        """Return True if target_dir (or its nearest existing ancestor) is accessible and writable."""
        try:
            check = target_dir
            while not check.exists():
                if check == check.parent:
                    return False
                check = check.parent
            return os.access(check, os.W_OK)
        except OSError:
            return False

    @staticmethod
    def get_aws_credentials_path(base_dir: Path | None = None) -> Path:
        """Return the target path for synthetic AWS credentials."""
        aws_path = Path.home() / ".aws" / "credentials.honey"
        if base_dir is not None and not CanaryDeployer._can_use_directory(aws_path.parent):
            return base_dir / "credentials.honey"
        return aws_path

    @staticmethod
    def get_chrome_cookies_path(base_dir: Path | None = None) -> Path:
        """Return the target path for synthetic Chrome cookies."""
        if sys.platform == "darwin":
            chrome_dir = (
                Path.home()
                / "Library"
                / "Application Support"
                / "Google"
                / "Chrome"
                / "Default"
            )
        elif sys.platform == "win32":
            localappdata = os.environ.get(
                "LOCALAPPDATA", str(Path.home() / "AppData" / "Local")
            )
            chrome_dir = (
                Path(localappdata) / "Google" / "Chrome" / "User Data" / "Default"
            )
        else:
            chrome_dir = Path.home() / ".config" / "google-chrome" / "Default"

        try:
            chrome_writable = chrome_dir.exists() and os.access(chrome_dir, os.W_OK)
        except OSError:
            chrome_writable = False

        if not chrome_writable and base_dir is not None:
            return base_dir / "Cookies.honey"
        return chrome_dir / "Cookies.honey"

    @staticmethod
    def get_system_config_path(base_dir: Path | None = None) -> Path:
        """Return the target path for synthetic system configuration."""
        if sys.platform == "darwin":
            sys_path = (
                Path.home()
                / "Library"
                / "Preferences"
                / "com.apple.deceptenv.sys.plist.honey"
            )
        elif sys.platform == "win32":
            appdata = os.environ.get(
                "APPDATA", str(Path.home() / "AppData" / "Roaming")
            )
            sys_path = (
                Path(appdata) / "Microsoft" / "Windows" / "deceptenv_config.ini.honey"
            )
        else:
            sys_path = Path.home() / ".config" / "deceptenv" / "system.conf.honey"

        if base_dir is not None and not CanaryDeployer._can_use_directory(sys_path.parent):
            return base_dir / sys_path.name
        return sys_path

    @staticmethod
    def get_env_file_path(base_dir: Path) -> Path:
        """Return the target path for synthetic .env file."""
        return base_dir / ".env.honey"

    def _safe_write(self, target_path: Path, content: bytes) -> Path:
        """Safely write a file ensuring no overwrites of non-canary files and strict permissions."""
        final_path = target_path
        try:
            if final_path.exists() and not final_path.name.endswith(".honey"):
                final_path = final_path.with_name(final_path.name + ".honey")
            final_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Fallback to configured base_dir if system directory access is denied
            final_path = self.base_dir / (
                final_path.name if final_path.name.endswith(".honey") else final_path.name + ".honey"
            )
            final_path.parent.mkdir(parents=True, exist_ok=True)

        if final_path.exists():
            # If the canary already exists, safely overwrite in place
            with open(final_path, "wb") as f:
                f.write(content)
        else:
            # Open with O_CREAT | O_EXCL to prevent race conditions on creation
            try:
                with open(final_path, "xb") as f:
                    f.write(content)
            except FileExistsError:
                with open(final_path, "wb") as f:
                    f.write(content)

        # Set restrictive permissions (600)
        try:
            os.chmod(final_path, 0o600)
        except OSError:
            pass
        return final_path

    def _get_deploy_key(self) -> bytes:
        """Return a persistent HMAC key, creating one on first use."""
        key_path = self.base_dir / ".deceptenv_hmac.key"
        try:
            if key_path.exists():
                return key_path.read_bytes()
        except OSError:
            pass
        key = secrets.token_bytes(32)
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(key)
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key

    def deploy_aws_credentials(self) -> Path:
        """Create a synthetic AWS credentials file."""
        target_path = self.get_aws_credentials_path(self.base_dir)

        access_key = f"AKIA{secrets.token_hex(8).upper()}"
        secret_key = secrets.token_hex(20)

        # Use persistent per-deployment HMAC key for verification
        hmac_key = self._get_deploy_key()
        signature = hmac.new(
            hmac_key, access_key.encode(), "sha256"
        ).hexdigest()

        content = f"""[default]
aws_access_key_id = {access_key}
aws_secret_access_key = {secret_key}
# DECEPTENV_SIG={signature}
# DECEPTENV_HMAC_KEY={hmac_key.hex()}
"""
        return self._safe_write(target_path, content.encode())

    def deploy_env_file(self) -> Path:
        """Create a plausible .env file trap."""
        target_path = self.get_env_file_path(self.base_dir)

        if not target_path.resolve().is_relative_to(self.base_dir.resolve()):
            raise SecurityBoundaryViolation(
                "Attempted to deploy canary outside configured directory."
            )

        content = f"""OPENAI_API_KEY=sk-{secrets.token_hex(24)}
DATABASE_URL=postgres://admin:{secrets.token_hex(8)}@localhost:5432/prod
STRIPE_SECRET_KEY=sk_live_{secrets.token_hex(24)}
"""
        return self._safe_write(target_path, content.encode())

    def deploy_chrome_cookies(self) -> Path:
        """Create a plausible SQLite database mimicking Chrome cookies in the real profile dir if possible."""
        target_path = self.get_chrome_cookies_path(self.base_dir)

        # If the target directory does not exist and base_dir was used, verify security boundary
        if self.base_dir.resolve() in target_path.resolve().parents:
            pass
        else:
            try:
                parent_exists = target_path.parent.exists()
            except OSError:
                parent_exists = False
            if not parent_exists:
                target_path = self.base_dir / "Cookies.honey"
                if not target_path.resolve().is_relative_to(self.base_dir.resolve()):
                    raise SecurityBoundaryViolation(
                        "Attempted to deploy canary outside configured directory."
                    )

        final_path = target_path
        try:
            if final_path.exists() and not final_path.name.endswith(".honey"):
                final_path = final_path.with_name(final_path.name + ".honey")
            final_path.parent.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                final_path.unlink()
        except OSError:
            final_path = self.base_dir / "Cookies.honey"
            final_path.parent.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                final_path.unlink()

        # Initialize SQLite DB matching Chromium schema (v130+)
        with sqlite3.connect(final_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE cookies (
                    creation_utc INTEGER NOT NULL,
                    host_key TEXT NOT NULL,
                    top_frame_site_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    value TEXT NOT NULL,
                    encrypted_value BLOB NOT NULL,
                    path TEXT NOT NULL,
                    expires_utc INTEGER NOT NULL,
                    is_secure INTEGER NOT NULL,
                    is_httponly INTEGER NOT NULL,
                    last_access_utc INTEGER NOT NULL,
                    has_expires INTEGER NOT NULL,
                    is_persistent INTEGER NOT NULL,
                    priority INTEGER NOT NULL,
                    samesite INTEGER NOT NULL,
                    source_scheme INTEGER NOT NULL,
                    source_port INTEGER NOT NULL,
                    is_same_party INTEGER NOT NULL,
                    last_update_utc INTEGER NOT NULL,
                    UNIQUE (host_key, top_frame_site_key, name, path)
                )
            """
            )

            domains = [".google.com", ".github.com", ".binance.com"]
            for domain in domains:
                encrypted_blob = secrets.token_bytes(32)
                cursor.execute(
                    """
                    INSERT INTO cookies (
                        creation_utc, host_key, top_frame_site_key, name, value, 
                        encrypted_value, path, expires_utc, is_secure, is_httponly, 
                        last_access_utc, has_expires, is_persistent, priority, 
                        samesite, source_scheme, source_port, is_same_party, last_update_utc
                    ) VALUES (
                        13350000000000000, ?, '', 'session', '', ?, '/', 13380000000000000, 
                        1, 1, 13350000000000000, 1, 1, 1, 0, 2, 443, 0, 13350000000000000
                    )
                """,
                    (domain, encrypted_blob),
                )
            conn.commit()

        try:
            os.chmod(final_path, 0o600)
        except OSError:
            pass
        return final_path

    def deploy_system_config(self) -> Path:
        """Create a platform-specific system configuration tripwire."""
        target_path = self.get_system_config_path(self.base_dir)
        if sys.platform == "darwin":
            content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeveloperToken</key>
    <string>dev_{secrets.token_hex(16)}</string>
</dict>
</plist>
"""
        elif sys.platform == "win32":
            content = f"""[System]
RegistryCacheToken=REG_{secrets.token_hex(16)}
"""
        else:
            content = f"""[Environment]
SSH_AGENT_TOKEN=ssh_{secrets.token_hex(16)}
"""

        return self._safe_write(target_path, content.encode())
