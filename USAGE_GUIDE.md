<!-- markdownlint-disable MD013 -->
# DeceptEnv: Complete Usage & Architecture Guide

## 🌟 What is DeceptEnv?

DeceptEnv is a **zero-privilege active defense engine** built to detect, attribute, and freeze **infostealers** before they can exfiltrate credentials, browser cookies, or API secrets.

Because infostealers execute under normal user permissions using standard file reads, signature AV and kernel EDR tools often allow those reads until exfiltration completes. DeceptEnv traps those reads in user space:

1. **Deception & Boundary Hardening (`CanaryDeployer`):** Creates realistic `0o600` honey-tokens (`credentials.honey`, atomic Chromium v130+ SQLite `Cookies.honey`, `.env.honey`, and OS config decoys) while rejecting symlinks (`SecurityBoundaryViolation`), computing persistent HMAC keys, and arming `st_atime < st_mtime` timestamps.
2. **Continuous Async Telemetry (`CanaryMonitor`):** Polls nanosecond `st_atime_ns` and `st_mtime_ns` changes every `10ms`, re-arming timestamps after every trigger so consecutive real reads stay detectable, buffered through a `1.0s` FIFO `asyncio.Queue` debouncer.
3. **Two-Tier Attribution & Prevention (`PlatformAdapter`, `ThreatMitigator`):** Attributes open file handles (or recent user processes within 5s excluding self, ancestors, `STATUS_STOPPED`, and `STATUS_ZOMBIE`), enforces UID/SID ownership and ancestor self-harm guards, and suspends offending threads (`SIGSTOP` / `NtSuspendProcess`).
4. **Bounded Forensics & Alerting (`ForensicsExtractor`, `SlackNotifier`, `web.py`):** Captures process ancestry lineage, open INET sockets, and bounded `2MB` memory strings (Linux `/proc/[pid]/mem`), serves an authenticated localhost Web Dashboard (`127.0.0.1:8080`), and optionally posts HTTPS-validated Slack Block Kit alerts.

---

## 💻 CLI & Web Dashboard Commands

Activate your virtual environment (`.venv/bin/activate` on macOS/Linux or `.venv\Scripts\Activate.ps1` on Windows) and use the `deceptenv` CLI:

- **`deceptenv --help`** — Display command options.
- **`deceptenv init`** — Deploy armed synthetic canaries (`credentials.honey`, `Cookies.honey`, `.env.honey`, and system config decoy).
- **`deceptenv list-canaries`** — Display active canary paths and status.
- **`deceptenv run`** — Start the live terminal telemetry console and active mitigation monitor.
- **`deceptenv dashboard`** — Start the interactive Web Telemetry Console on `http://127.0.0.1:8080`.
- **`deceptenv clean`** — Unlink all deployed `.honey` decoy files.

### Sandboxed Attack Simulation Proof

Run the standalone unmodified-read simulation script at any time:

```bash
python tests/simulation/attack_simulator.py
# Or:
make simulate
```

See [VERIFICATION_PROOF.md](VERIFICATION_PROOF.md) and [README.md](README.md#5-verified-simulation--prevention-proof-observed-output) for captured simulation outputs and test metrics.

---

## 🖥️ Operating System Specifics

### 🍎 macOS

- **Default Canary Locations (with automatic fallback to `DECEPTENV_CANARY_DIR` / `./.deceptenv_canaries` if macOS TCC blocks `$HOME` paths):**
  - AWS: `~/.aws/credentials.honey`
  - Chrome: `~/Library/Application Support/Google/Chrome/Default/Cookies.honey`
  - System: `~/Library/Preferences/com.apple.deceptenv.sys.plist.honey`
  - Workspace: `./.deceptenv_canaries/.env.honey`
- **Under the hood:** Uses `10ms` `st_atime_ns`/`st_mtime_ns` polling (`st_atime < st_mtime` armed on APFS), `psutil.Process.open_files()` + Tier 2 attribution, and `os.kill(pid, signal.SIGSTOP)` to freeze threads in user space.
- **How to test:**

  ```bash
  # Terminal 1:
  deceptenv init
  deceptenv run

  # Terminal 2:
  python3 -c 'import time; print(len(open(".deceptenv_canaries/.env.honey", "rb").read())); time.sleep(10)' &
  ps -o pid,stat,command -p $!   # STAT shows T (stopped)
  ```

### 🐧 Linux

- **Default Canary Locations:**
  - AWS: `~/.aws/credentials.honey`
  - Chrome: `~/.config/google-chrome/Default/Cookies.honey` (fallback `canary_directory`)
  - System: `~/.config/deceptenv/system.conf.honey`
  - Workspace: `./.deceptenv_canaries/.env.honey`
- **Under the hood:** Uses `10ms` `st_atime_ns`/`st_mtime_ns` polling (`relatime`-compatible arming), `/proc/[pid]/fd` descriptor matching + Tier 2 attribution, `SIGSTOP` freezing, and bounded `2MB` `/proc/[pid]/mem` C2 string extraction (skipping `[vvar]`, `[vdso]`, `[vsyscall]`).
- **How to test:**

  ```bash
  # Terminal 1:
  deceptenv init
  deceptenv run

  # Terminal 2:
  python3 -c 'import time; open(".deceptenv_canaries/.env.honey", "rb").read(); time.sleep(10)' &
  ps -eo pid,stat,cmd | grep python3
  ```

### 🪟 Windows (PowerShell)

- **Default Canary Locations:**
  - AWS: `%USERPROFILE%\.aws\credentials.honey`
  - Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies.honey` (fallback `canary_directory`)
  - System: `%APPDATA%\Microsoft\Windows\deceptenv_config.ini.honey`
  - Workspace: `.deceptenv_canaries\.env.honey`
- **Under the hood:** Uses `10ms` `st_atime_ns`/`st_mtime_ns` polling, Windows Restart Manager (`rstrtmgr.dll`) + Tier 2 attribution, `advapi32` SID ownership checks, and `ntdll.NtSuspendProcess` to suspend threads under Medium Integrity without Administrator elevation.
- **How to test (PowerShell):**

  ```powershell
  # Window 1:
  deceptenv init
  deceptenv run

  # Window 2:
  $proc = Start-Process python -ArgumentList '-c', 'import time; open(".deceptenv_canaries/.env.honey", "rb").read(); time.sleep(10)' -PassThru
  Start-Sleep -Milliseconds 500
  (Get-Process -Id $proc.Id).Threads | Select-Object Id, ThreadState, WaitReason
  ```

---

## ⚙️ Configuration, Web Auth & Slack Integration

Config values can be placed in `./deceptenv.json`, `./.deceptenv.json`, or `~/.config/deceptenv/config.json`, or overridden via environment variables:

```bash
# Custom canary directory
export DECEPTENV_CANARY_DIR="$PWD/.deceptenv_canaries"

# Optional Bearer token authentication for the Web Dashboard REST APIs
export DECEPTENV_DASHBOARD_TOKEN="your-secret-bearer-token"
deceptenv dashboard

# Optional HTTPS Slack webhook alerts
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
deceptenv run
```
