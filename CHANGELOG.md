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
- **Verification Proof**: Added `VERIFICATION_PROOF.md` and sandboxed attacker neutralization + forensic capture E2E test in `tests/simulation/test_e2e.py`
- **Packaging**: Declared MIT license metadata (`license = { file = "LICENSE" }`) and PyPI classifiers in `pyproject.toml`

### Fixed

- **APFS / relatime Continuous Detection (`deployer.py`, `monitor.py`)**: Armed canary timestamps (`st_atime < st_mtime`) upon deployment, monitor startup, and post-event re-arming with nanosecond `st_atime_ns`/`st_mtime_ns` tracking so real unmodified reads (even consecutive reads) always advance `st_atime` cleanly; tracked active callback tasks and dynamically synced registered paths
- **Symlink & SQLite Creation Prevention (`deployer.py`)**: Explicitly rejected symlink targets (`SecurityBoundaryViolation`) and used private `0o600` temp file + `os.replace()` for `deploy_chrome_cookies()`
- **Self-Harm & Python 3.9 Lock Safety (`mitigator.py`, `base.py`, `darwin.py`, `linux.py`, `windows.py`)**: Guarded full ancestor lineage against self-freeze, lazily initialized `asyncio.Lock` for Python 3.9 sync safety, added cycle protection to `get_process_lineage()`, and excluded `STATUS_STOPPED`/`STATUS_ZOMBIE` + ancestors from Tier 2 attribution
- **Forensic URL & Memory Region Extraction (`forensics.py`)**: Expanded `URL_REGEX` to retain full path/port/query parameters, skipped special kernel pages (`[vvar]`, `[vdso]`, `[vsyscall]`), and handled memory read errors per region instead of aborting the dump
- **Config, Web & CLI Lifecycle (`config.py`, `web.py`, `cli.py`)**: Enforced full HTTPS+host URL parsing on `slack_webhook_url`, ensured simulation subprocess teardown in `finally:` on web errors, checked auth in `do_HEAD`, registered `/api/init` paths, warmed `psutil.cpu_percent`, and cancelled/awaited tasks cleanly in `async_run()`

### Security

- Dashboard API endpoints enforce timing-safe (`secrets.compare_digest`) Bearer token authentication for both `config.dashboard_auth_token` and `DECEPTENV_DASHBOARD_TOKEN`, with browser UI session prompt support
- Platform adapters (`DarwinAdapter`, `LinuxAdapter`, `WindowsAdapter`), CLI, and Web Dashboard consistently honor `base_dir` fallback paths when `~/.aws` or `~/Library/Preferences` deny access
- Removed legacy tracked scratch artifacts (`scratch/*`, `test_atime.txt`, `test_file.txt`) from git tracking
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
