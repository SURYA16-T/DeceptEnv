<!-- markdownlint-disable MD013 -->
# DeceptEnv: Zero-Privilege Active Defense & Infostealer Neutralization Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

DeceptEnv is a cross-platform, unprivileged endpoint defense daemon designed to detect, attribute, and freeze suspicious processes that interact with deception canaries in real time (benchmarked under `<200ms` end-to-end).

By leveraging OS-level process ownership rules, DeceptEnv traps unauthorized credential access in user space and suspends offending processes at the kernel scheduler level—without requiring `sudo`, Administrator privileges, or kernel-mode drivers.

---

## Table of Contents

1. [The Problem: The User-Space EDR Blindspot](#1-the-problem-the-user-space-edr-blindspot)
2. [How DeceptEnv Works & Prevention Architecture](#2-how-deceptenv-works--prevention-architecture)
3. [Cross-Platform Technical Matrix](#3-cross-platform-technical-matrix)
4. [Step-by-Step Setup & Execution Across All Three OSes](#4-step-by-step-setup--execution-across-all-three-oses)
   - [Configuration Reference](#-configuration-optional)
   - [macOS Step-by-Step](#-macos-step-by-step)
   - [Linux Step-by-Step](#-linux-step-by-step)
   - [Windows Step-by-Step](#-windows-step-by-step-powershell)
5. [Verified Simulation & Prevention Proof (Observed Output)](#5-verified-simulation--prevention-proof-observed-output)
6. [Documentation & License](#6-documentation--license)

---

## 1. The Problem: The User-Space EDR Blindspot

Modern infostealers do not need privilege escalation. They execute under standard user permissions and harvest sensitive files directly from `$HOME` / `%USERPROFILE%`:

- **Cloud configurations:** `~/.aws/credentials`, `~/.config/gcloud/`
- **Browser vaults:** Chromium/Chrome SQLite `Cookies` and login stores
- **Developer secrets:** `.env` workspace keys, system config plists/ini tokens

Because reading a user-owned file is normal, signature AV and enterprise EDRs routinely permit it. Seconds later, the payload archives those secrets and exfiltrates them over HTTPS.

```text
[ Traditional Attack Chain ]
Payload Executed ──► Scans ~/.aws, Cookies, .env ──► Archives Secrets ──► Exfiltrates to C2 (Data Lost)

[ DeceptEnv Active Prevention Chain ]
Payload Executed ──► Reads Armed Canary ──► Monitor Intercepts (<200ms) ──► SIGSTOP / NtSuspendProcess (Frozen)
```

---

## 2. How DeceptEnv Works & Prevention Architecture

DeceptEnv executes a five-stage active defense and prevention pipeline inside standard user permissions:

```text
                    [ INCOMING USER-SPACE PROCESS ]
                    (Rogue Dependency / Infostealer / Script)
                                     │
                                     ▼
                [ Evaluates Credential Targets in User Profile ]
                                     │
                  ┌──────────────────┴──────────────────┐
                  ▼                                     ▼
          [ Legitimate Data ]                  [ Armed Synthetic Canaries ]
          (~/.aws/credentials)                 (credentials.honey / Cookies.honey / .env.honey)
                  │                                     │
                  │ (Normal Workload)                   │ (Unauthorized Read / Tamper)
                  ▼                                     ▼
          [ Read Permitted ]                 [ CanaryMonitor Event ]
                                             (10ms st_atime_ns / st_mtime_ns poll)
                                                        │
                                                        ▼
                                             ┌──────────────────────┐
                                             │ Two-Tier Attributor  │
                                             │ Tier 1: Open FDs/RM  │
                                             │ Tier 2: 5s Heuristic │
                                             └──────────┬───────────┘
                                                        │
                                                        ▼
                                             ┌──────────────────────┐
                                             │   ThreatMitigator    │
                                             │ Self/Ancestor Guard  │
                                             │ UID/SID Match Check  │
                                             └──────────┬───────────┘
                                                        │
                         ┌──────────────────────────────┴──────────────────────────────┐
                         ▼                                                             ▼
              [ Thread Suspension ]                                         [ Bounded Forensics ]
          Linux / macOS: SIGSTOP                                         - Process Ancestry Lineage
          Windows: NtSuspendProcess                                      - Open INET Network Sockets
          (Exfiltration halted in scheduler)                             - Scrapes Memory (Max 2MB, POSIX /proc)
```

### Active Prevention & Security Controls Enforced in Code

1. **Synthetic Canary Hardening (`CanaryDeployer` in `src/deceptenv/canary/deployer.py`)**
   - **Strict Permissions & Atomic SQLite Creation:** Deploys `.env.honey`, `credentials.honey`, OS config tripwires, and Chromium v130+ `Cookies.honey` with `0o600` permissions. `deploy_chrome_cookies()` builds the SQLite database inside a private `0o600` temporary file and swaps it atomically via `os.replace()`.
   - **Symlink Redirect Prevention:** Rejects any symlink target (`is_symlink()` -> `SecurityBoundaryViolation`) so an attacker cannot trick `deceptenv init` into overwriting legitimate files via pre-planted links.
   - **Path Boundary & Deny-List Validation (`SecurityConfig`):** Canonicalizes `canary_directory` via `Path.resolve()`, blocks forbidden system roots (`/`, `/bin`, `/sbin`, `/etc`, `/usr`, `/var`, `/System`, `/Library`, `/boot`, `/dev`, `/proc`, `/sys`), and falls back gracefully to `canary_directory` if `$HOME` directories reject writes (`PermissionError` / macOS TCC).
   - **Persistent HMAC Verification Keys:** Generates and persists a 32-byte `.deceptenv_hmac.key` (`0o600`) to tag synthetic AWS keys for stolen-token attribution.
   - **APFS & `relatime` Timestamp Arming:** Sets `st_atime < st_mtime` (`st_mtime - 10s`) upon deployment so macOS APFS and Linux `relatime` always bump `st_atime_ns` on genuine unmodified file reads.
2. **Continuous Asynchronous Telemetry (`CanaryMonitor` in `src/deceptenv/engine/monitor.py`)**
   - Polls nanosecond `st_atime_ns` and `st_mtime_ns` across registered and target paths every `10ms`, re-arming `st_atime < st_mtime` after every triggered event so consecutive real reads continue firing.
   - Buffers detections through an `asyncio.Queue` with a `1.0s` per-path debouncer and tracks active callback tasks cleanly.
3. **Two-Tier Process Attribution (`src/deceptenv/platform/`)**
   - **Tier 1 (Exact Handle Lookup):** Scans open file descriptors (`/proc/[pid]/fd` on Linux, `psutil.Process.open_files()` on macOS, Windows Restart Manager `rstrtmgr.dll` on Windows).
   - **Tier 2 (Fast-Close Heuristic Fallback):** Inspects processes spawned within the past `5s` matching the current user UID/SID while excluding `os.getpid()`, `os.getppid()`, full ancestor lineage, and already `STATUS_STOPPED`/`STATUS_ZOMBIE` processes so frozen threats never shadow new attacks.
4. **Scheduler-Level Prevention (`ThreatMitigator` in `src/deceptenv/engine/mitigator.py`)**
   - **Self-Harm & Shell Protection:** Refuses to act on `pid <= 0`, own PID, `ppid`, or any PID in `get_process_lineage(os.getpid())`.
   - **Privilege Boundary Guard:** Cross-checks process owner (`UID` on POSIX, `SID` on Windows) before issuing suspension, raising `ProcessOwnershipViolation` on mismatch.
   - **Race-Safe Lock & Uncatchable Freeze:** Acquires a lazy `asyncio.Lock` and freezes offending threads via `os.kill(pid, signal.SIGSTOP)` or `ntdll.NtSuspendProcess` rather than killing the process (`SIGKILL`), keeping volatile memory intact for inspection.
5. **Bounded Forensics, Alerting & Authenticated Console (`ForensicsExtractor`, `SlackNotifier`, `web.py`)**
   - Extracts process ancestry tree (`get_process_lineage` with cycle guard), active INET sockets, and C2 URLs (full scheme, host, port, path, query), IPv4s, and Base64 strings from Linux `/proc/[pid]/mem` capped at `2MB` (`max_forensic_dump_size_bytes`), skipping unreadable kernel pages (`[vvar]`, `[vdso]`, `[vsyscall]`) per region.
   - Validates `slack_webhook_url` (`https` + valid host) and serves a `127.0.0.1:8080` telemetry dashboard with HTML entity escaping (`escapeHtml`) and timing-safe Bearer authentication (`secrets.compare_digest` via `DECEPTENV_DASHBOARD_TOKEN`).

---

## 3. Cross-Platform Technical Matrix

| Subsystem | Linux | macOS | Windows |
| :--- | :--- | :--- | :--- |
| **Filesystem Telemetry** | `10ms` `st_atime_ns`/`st_mtime_ns` polling (`relatime` armed) | `10ms` `st_atime_ns`/`st_mtime_ns` polling (APFS armed) | `10ms` `st_atime_ns`/`st_mtime_ns` polling |
| **PID Attribution** | `/proc/[pid]/fd` + Tier 2 heuristic | `psutil.open_files()` + Tier 2 heuristic | Restart Manager (`rstrtmgr.dll`) + Tier 2 heuristic |
| **Thread Suspension** | `os.kill(pid, signal.SIGSTOP)` | `os.kill(pid, signal.SIGSTOP)` | `ntdll.NtSuspendProcess` |
| **Memory String Dump** | Bounded `2MB` via `/proc/[pid]/mem` | Socket & ancestry lineage (`no /proc`) | Socket & ancestry lineage |
| **Privilege Required** | Standard User (`UID != 0`) | Standard User (Non-wheel / TCC resilient) | Medium Integrity (Non-Admin) |

---

## 4. Step-by-Step Setup & Execution Across All Three OSes

### Configuration (Optional)

Configuration is loaded in order from:
1. `./deceptenv.json`, `./.deceptenv.json`, or `~/.config/deceptenv/config.json`
2. Environment variables (highest priority):
   - `DECEPTENV_CANARY_DIR` — custom base canary directory (default: `./.deceptenv_canaries`)
   - `DECEPTENV_DASHBOARD_TOKEN` — Bearer token protecting `/api/*` dashboard endpoints
   - `SLACK_WEBHOOK_URL` — `https://...` Slack webhook URL for live Block Kit alerts

---

### 🍎 macOS Step-by-Step

> Verified end-to-end on macOS (`Darwin arm64`) inside both standard shells and restricted Seatbelt sandboxes.

1. **Install Python 3.9+ and clone the repository:**

   ```bash
   git clone https://github.com/SURYA16-T/DeceptEnv.git
   cd DeceptEnv/deceptenv
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. **Deploy deceptive tripwires (`deceptenv init`):**

   ```bash
   deceptenv init
   ```

   Deploys up to 4 armed `0o600` decoys (`~/.aws/credentials.honey`, Chrome `Cookies.honey`, `~/Library/Preferences/com.apple.deceptenv.sys.plist.honey`, and `./.deceptenv_canaries/.env.honey`). If macOS TCC / sandbox denies access to `~/Library` or `~/.aws`, DeceptEnv automatically falls back to `DECEPTENV_CANARY_DIR` (or `./.deceptenv_canaries/`).

3. **Verify deployed canaries (`deceptenv list-canaries`):**

   ```bash
   deceptenv list-canaries
   ```

4. **Start active monitoring (Terminal 1) or launch Web Telemetry Console:**

   ```bash
   # Terminal 1 — Active terminal telemetry monitor
   deceptenv run

   # OR launch interactive localhost dashboard at http://127.0.0.1:8080
   export DECEPTENV_DASHBOARD_TOKEN="choose-a-strong-token"   # optional auth
   deceptenv dashboard
   ```

5. **Simulate an attacker read & verify suspension (Terminal 2):**

   ```bash
   # Trigger an unauthorized read against a workspace canary
   python3 -c 'import time; print(len(open(".deceptenv_canaries/.env.honey", "rb").read())); time.sleep(10)' &
   ATTACKER_PID=$!

   # Observe the OS scheduler state — "T" indicates stopped (SIGSTOP)
   sleep 0.5
   ps -o pid,stat,command -p $ATTACKER_PID
   ```

6. **Clean up frozen process and remove decoys:**

   ```bash
   kill -CONT $ATTACKER_PID && kill $ATTACKER_PID
   deceptenv clean
   ```

---

### 🐧 Linux Step-by-Step

> Verified via unit suites and GitHub Actions CI (`ubuntu-latest` matrix for Python 3.9, 3.11, 3.12).

1. **Install prerequisites, create `.venv`, and install DeceptEnv:**

   ```bash
   sudo apt-get update && sudo apt-get install -y python3 python3-venv git  # Debian/Ubuntu
   git clone https://github.com/SURYA16-T/DeceptEnv.git
   cd DeceptEnv/deceptenv
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. **Deploy synthetic canaries:**

   ```bash
   deceptenv init
   deceptenv list-canaries
   ```

   Target locations on Linux: `~/.aws/credentials.honey`, `~/.config/google-chrome/Default/Cookies.honey` (or `canary_directory`), `~/.config/deceptenv/system.conf.honey`, and `./.deceptenv_canaries/.env.honey`.

3. **Start the unprivileged daemon (Terminal 1) or Web Console:**

   ```bash
   # Optional Slack alert integration
   export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
   deceptenv run
   # Or: deceptenv dashboard
   ```

4. **Trigger a read & verify `/proc/[pid]/mem` forensics and `SIGSTOP` freeze (Terminal 2):**

   ```bash
   python3 -c 'import time; d=open(".deceptenv_canaries/.env.honey","rb").read(); u="https://c2.example/exfil"; time.sleep(10)' &
   ATTACKER_PID=$!
   sleep 0.5
   ps -o pid,stat,cmd -p $ATTACKER_PID
   ```

   Terminal 1 attributes the caller via `/proc/[pid]/fd`, suspends it (`STAT = T`), and extracts lineage, sockets, and matching URLs/IPs/Base64 strings up to `2MB` from `/proc/[pid]/mem` (`CAP_SYS_PTRACE` is not required for your own processes when `kernel.yama.ptrace_scope` allows child/user access, otherwise lineage + sockets are still captured cleanly).

5. **Clean up:**

   ```bash
   kill -CONT $ATTACKER_PID && kill $ATTACKER_PID
   deceptenv clean
   ```

---

### 🪟 Windows Step-by-Step (PowerShell)

> Implemented using `ctypes` Restart Manager (`rstrtmgr.dll`), `advapi32` SID verification, and `ntdll.NtSuspendProcess` (tested via contract/mock unit suites; run locally on Windows 10/11 under a standard Medium Integrity PowerShell prompt).

1. **Clone repository and install in a virtual environment:**

   ```powershell
   git clone https://github.com/SURYA16-T/DeceptEnv.git
   cd DeceptEnv\deceptenv
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -e ".[dev]"
   ```

2. **Deploy synthetic canaries (no Administrator prompt needed):**

   ```powershell
   deceptenv init
   deceptenv list-canaries
   ```

   Target locations on Windows: `%USERPROFILE%\.aws\credentials.honey`, `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies.honey` (or `canary_directory`), `%APPDATA%\Microsoft\Windows\deceptenv_config.ini.honey`, and `.deceptenv_canaries\.env.honey`.

3. **Start DeceptEnv active defense (Window 1) or Web Dashboard:**

   ```powershell
   deceptenv run
   # Or:
   # $env:DECEPTENV_DASHBOARD_TOKEN = "choose-a-strong-token"
   # deceptenv dashboard
   ```

4. **Simulate unauthorized credential access (Window 2):**

   ```powershell
   $proc = Start-Process python -ArgumentList '-c', 'import time; open(".deceptenv_canaries/.env.honey", "rb").read(); time.sleep(10)' -PassThru
   Start-Sleep -Milliseconds 500
   (Get-Process -Id $proc.Id).Threads | Select-Object Id, ThreadState, WaitReason
   ```

   WaitState transitions to `Wait` / `WaitReason: Suspended` via `NtSuspendProcess`, halting execution prior to exfiltration.

5. **Terminate test process and clean decoys:**

   ```powershell
   Stop-Process -Id $proc.Id -Force
   deceptenv clean
   ```

---

## 5. Verified Simulation & Prevention Proof (Observed Output)

All outputs below were captured verbatim in this workspace under Python `3.9.6` on macOS (`Darwin arm64`) inside a restricted Seatbelt sandbox (full details also recorded in [VERIFICATION_PROOF.md](VERIFICATION_PROOF.md)).

### A. Live Real-Read Sandboxed Attacker Simulation (`tests/simulation/attack_simulator.py`)

Spawns an unmodified rogue Python infostealer process that reads `.env.honey` (with **no** `os.utime()` helper) and attempts to sleep before printing `"Exfiltration Complete"`. `CanaryMonitor` intercepts the real file read, `ThreatMitigator` freezes the attacker with `SIGSTOP`, extracts process lineage, and blocks exfiltration:

```bash
.venv/bin/python tests/simulation/attack_simulator.py
```

```text
[*] Deployed sandbox canary at /private/var/folders/6f/8d5yx3510xz72h8vqkhmrfz00000gn/T/deceptenv_sim_yzcawr_m/canaries/.env.honey
[*] Spawning real unmodified infostealer child process...
PID attribution via heuristic fallback (Tier 2): PID 4664. Confidence: LOW — based on most-recently-spawned process within 5s window.
Successfully suspended threat process: PID 4664
[*] Monitor intercepted read on .env.honey -> froze PID 4664
[+] Forensic Report Extracted:
{
  "lineage": [
    {
      "pid": 4664,
      "ppid": 4663,
      "name": "Python",
      "cmdline": [
        "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python",
        "/var/folders/6f/8d5yx3510xz72h8vqkhmrfz00000gn/T/deceptenv_sim_yzcawr_m/rogue_stealer.py"
      ]
    },
    {
      "pid": 4663,
      "ppid": 3397,
      "name": "Python",
      "cmdline": [
        "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python",
        "tests/simulation/attack_simulator.py"
      ]
    },
    ...
  ],
  "network_sockets": [],
  "extracted_urls": [],
  "extracted_ips": [],
  "extracted_base64": []
}
[+] Scheduler freeze completed in 3.30ms
[*] Verifying frozen process stays suspended for 2s...
[+] SUCCESS: Real-read infostealer simulation completely neutralized.
```

### B. Automated Sandboxed E2E Suite & Latency Benchmark (`tests/simulation/test_e2e.py`)

Tests genuine unmodified infostealer detection (`test_end_to_end_neutralization`), false-positive rejection on non-canary reads (`test_negative_unrelated_file`), end-to-end latency SLA (`test_end_to_end_latency_benchmark`), and consecutive real-read exfiltration blocking (`test_sandboxed_attacker_exfiltration_blocked_with_forensics`):

```bash
.venv/bin/python -m pytest tests/simulation/test_e2e.py -v -s --tb=short
```

```text
============================= test session starts ==============================
platform darwin -- Python 3.9.6, pytest-8.4.2, pluggy-1.6.0
collecting ...
collected 4 items

tests/simulation/test_e2e.py ..
--- BENCHMARK RESULTS ---
Total Simulation Latency (Start -> Frozen): 172.14 ms
..

============================== 4 passed in 3.07s ===============================
```

### C. Web Dashboard Simulation & Armed Canary Telemetry Proof (`deceptenv.web`)

Verified `execute_attack_simulation()` and `get_canary_list()` in an isolated temporary directory (`DECEPTENV_CANARY_DIR`):

```text
Successfully suspended threat process: PID 4690
SIM_SUMMARY: {
  "success": true,
  "pid": 4690,
  "latency_ms": 1.97,
  "status": "NEUTRALIZED",
  "target": ".env.honey"
}
ARMED_COUNT: 4 / 4
  - aws_credentials: credentials.honey | ARMED | 283B | d51a8d100bdbd50e...
  - chrome_cookies: Cookies.honey | ARMED | 12288B | 466b586e7912bab2...
  - system_config: com.apple.deceptenv.sys.plist.honey | ARMED | 276B | 98bb573b3b8d7a6c...
  - env_file: .env.honey | ARMED | 209B | c430c9d570804fd6...
```

### D. Full Quality Assurance Verification

```bash
ruff check src/ tests/
mypy src/ --ignore-missing-imports
pytest tests/ -v -s --cov=deceptenv --cov-report=term-missing --tb=short
```

| Verification Suite | Outcome |
| :--- | :--- |
| `ruff check src/ tests/` | All checks passed (`E`, `F`, `B`, `S`, `I`) |
| `mypy src/ --ignore-missing-imports` | Success: no issues found in 18 source files (`strict = true`) |
| `pytest tests/` (unit + E2E simulation) | **74 passed in 3.60s** (`66%` overall coverage; `config.py` `100%`, `registry.py` `100%`, `notifier.py` `94%`, `forensics.py` `92%`, `monitor.py` `90%`, `mitigator.py` `86%`, `darwin.py` `84%`) |

---

## 6. Documentation & License

- [VERIFICATION_PROOF.md](VERIFICATION_PROOF.md) — Complete verification log and prevention controls checklist
- [USAGE_GUIDE.md](USAGE_GUIDE.md) — Additional CLI & Slack webhook setup walkthrough
- [CAPSTONE_REPORT.md](CAPSTONE_REPORT.md) — Academic threat model and architectural design report
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development setup, style rules, and security guidelines
- [CHANGELOG.md](CHANGELOG.md) — Release history (`v0.1.0`)
- [LICENSE](LICENSE) — Distributed under the **MIT License**

## Disclaimer

DeceptEnv is built for defensive threat mitigation, behavioral process auditing, and educational security research. Ensure proper authorization before testing in managed or production environments.
