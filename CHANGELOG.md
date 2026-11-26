# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-26

### Added

- **Core Engine**: Zero-privilege active defense daemon with canary tripwire monitoring
- **Canary Deployer**: Deploys synthetic AWS credentials, Chrome cookies (SQLite), `.env` files, and system config tripwires
- **Platform Adapters**: Linux (`/proc` fd scanning + SIGSTOP), macOS (psutil + SIGSTOP), Windows (Restart Manager + NtSuspendProcess)
- **Forensics Extractor**: Bounded memory dumping (2MB limit), process lineage extraction, network socket snapshot, regex-based URL/IP/base64 extraction
- **Threat Mitigator**: Race-condition-safe process freezing with self-harm prevention, ownership verification, and async locking
- **Canary Monitor**: 10ms async polling loop with debouncing for sub-200ms detection latency
- **Slack Notifier**: Async Block Kit webhook integration for incident alerts
- **CLI**: `init`, `run`, `list-canaries`, `clean`, and `dashboard` commands via Typer
- **Web Dashboard**: Real-time threat telemetry console with live attack simulation, canary management, and incident forensics viewer
- **Dashboard Auth**: Optional Bearer token authentication for API endpoints (`DECEPTENV_DASHBOARD_TOKEN`)
- **Config System**: JSON file config with environment variable overrides, Pydantic validation, forbidden path deny-list
- **Security Hardening**: XSS protection (escapeHtml), temp file race prevention, persistent HMAC keys, comprehensive OSError/PermissionError handling for sandboxed environments (macOS TCC)

### Security

- Dashboard API endpoints enforce Bearer token authentication when `dashboard_auth_token` is configured
- HMAC signing keys are now persistent per-deployment (not ephemeral per-call)
- All dynamic HTML values sanitized via `escapeHtml()` to prevent XSS
- Temporary simulation scripts use `NamedTemporaryFile` with cleanup to prevent predictable path attacks
- Comprehensive `try/except OSError` wrapping for all filesystem operations in sandboxed environments

### DevOps

- GitHub Actions CI pipeline with lint + typecheck + test matrix (Python 3.9, 3.11, 3.12)
- Pre-commit hooks for ruff and mypy
- Makefile with common development commands
- Dockerfile with multi-stage build and non-root runtime user
- PEP 561 `py.typed` marker file
