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

    def _safe_write(self, target_path: Path, content: bytes) -> Path:
        """Safely write a file ensuring no overwrites and strict permissions."""
        final_path = target_path
        if final_path.exists():
            if not final_path.name.endswith(".honey"):
                final_path = final_path.with_name(final_path.name + ".honey")
        
        # Ensure directory exists
        final_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Open with O_CREAT | O_EXCL to prevent race conditions on creation
        try:
            with open(final_path, "xb") as f:
                f.write(content)
        except FileExistsError:
            final_path = final_path.with_name(final_path.name + ".honey")
            with open(final_path, "xb") as f:
                f.write(content)
        
        # Set restrictive permissions (600)
        os.chmod(final_path, 0o600)
        return final_path

    def deploy_aws_credentials(self) -> Path:
        """Create a synthetic AWS credentials file."""
        aws_dir = Path.home() / ".aws"
        target_path = aws_dir / "credentials.honey"
        
        access_key = f"AKIA{secrets.token_hex(8).upper()}"
        secret_key = secrets.token_hex(20)
        
        # Create an HMAC signature to verify it's our canary if stolen
        signature = hmac.new(
            b"deceptenv_aws_secret", access_key.encode(), "sha256"
        ).hexdigest()
        
        content = f"""[default]
aws_access_key_id = {access_key}
aws_secret_access_key = {secret_key}
# DECEPTENV_SIG={signature}
"""
        return self._safe_write(target_path, content.encode())

    def deploy_env_file(self) -> Path:
        """Create a plausible .env file trap."""
        target_path = self.base_dir / ".env.honey"
        
        if self.base_dir.resolve() not in target_path.resolve().parents:
            raise SecurityBoundaryViolation(
                "Attempted to deploy canary outside configured directory."
            )
            
        content = f"""OPENAI_API_KEY=sk-{secrets.token_hex(24)}
DATABASE_URL=postgres://admin:{secrets.token_hex(8)}@localhost:5432/prod
STRIPE_SECRET_KEY=sk_live_{secrets.token_hex(24)}
"""
        return self._safe_write(target_path, content.encode())

    def deploy_chrome_cookies(self) -> Path:
        """Create a plausible SQLite database mimicking Chrome cookies."""
        target_path = self.base_dir / "Cookies.honey"
        
        if self.base_dir.resolve() not in target_path.resolve().parents:
            raise SecurityBoundaryViolation(
                "Attempted to deploy canary outside configured directory."
            )
            
        final_path = target_path
        if final_path.exists():
            final_path = final_path.with_name(final_path.name + ".honey")
            if final_path.exists():
                final_path = final_path.with_name(final_path.name + ".honey")
        
        final_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create empty file exclusively
        with open(final_path, "xb"):
            pass
        os.chmod(final_path, 0o600)
        
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
            
        return final_path

    def deploy_system_config(self) -> Path:
        """Create a platform-specific system configuration tripwire."""
        if sys.platform == "darwin":
            # macOS: Fake preferences plist
            prefs_dir = Path.home() / "Library" / "Preferences"
            prefs_dir.mkdir(parents=True, exist_ok=True)
            target_path = prefs_dir / "com.apple.deceptenv.sys.plist.honey"
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
            # Windows: Fake AppData configuration
            appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
            prefs_dir = Path(appdata) / "Microsoft" / "Windows"
            prefs_dir.mkdir(parents=True, exist_ok=True)
            target_path = prefs_dir / "deceptenv_config.ini.honey"
            content = f"""[System]
RegistryCacheToken=REG_{secrets.token_hex(16)}
"""
        else:
            # Linux: Fake user systemd or generic config
            prefs_dir = Path.home() / ".config" / "deceptenv"
            prefs_dir.mkdir(parents=True, exist_ok=True)
            target_path = prefs_dir / "system.conf.honey"
            content = f"""[Environment]
SSH_AGENT_TOKEN=ssh_{secrets.token_hex(16)}
"""
            
        return self._safe_write(target_path, content.encode())
