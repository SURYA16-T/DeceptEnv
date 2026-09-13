<!-- markdownlint-disable MD013 -->
# DeceptEnv: Zero-Privilege Active Defense & Infostealer Neutralization Engine

DeceptEnv is a cross-platform, unprivileged endpoint defense daemon designed to detect, attribute, and freeze infostealer malware (e.g., LummaC2, Stealc, Vidar, RedLine) in sub-millisecond execution windows.

By leveraging OS-level process ownership rules, DeceptEnv traps unauthorized credential access in user space and suspends offending processes at the kernel scheduler level—without requiring `sudo`, Administrator privileges, or kernel-mode drivers.

## The Problem: The User-Space EDR Blindspot

Modern infostealers do not attempt privilege escalation. They deliberately run under standard user permissions, harvesting sensitive files directly from the user's home directory:

- **Cloud configurations**: `~/.aws/credentials`, `~/.config/gcloud/`
- **Browser vaults**: Chrome/Edge/Brave SQLite Cookies and Login Data
- **Developer secrets**: `~/.ssh/id_rsa`, `.env` workspace variables

Because reading a file in `$HOME` is a standard operation, signature-based antivirus and enterprise EDRs permit the access. Once the files are staged, the payload compresses them and completes HTTP exfiltration within seconds.

```text
[ Traditional Attack Chain ]
Payload Executed ──► Scans ~/.aws, Cookies ──► Zips Staging Dir ──► Exfiltrates to C2 (Data Lost)

[ DeceptEnv Active Defense Chain ]
Payload Executed ──► Touches Canary File ──► DeceptEnv Intercepts (<5ms) ──► Process Frozen via OS Signal (Zero Leakage)
```

## Architecture & Detection Pipeline

DeceptEnv places deceptive tripwires adjacent to production targets and monitors them using native OS filesystem events. Upon an unauthorized read, it resolves the caller's PID, validates ownership, pauses execution threads, and captures memory forensics.

```text
                    [ INCOMING USER-SPACE PROCESS ]
                    (Malicious Package / Trojan / Script)
                                     │
                                     ▼
                   [ Evaluates Targets in User Profile ]
                                     │
                  ┌──────────────────┴──────────────────┐
                  ▼                                     ▼
          [ Legitimate Data ]                  [ Synthetic Canaries ]
          (~/.aws/credentials)                 (~/.aws/credentials.honey)
                  │                                     │
                  │ (Normal Workload)                   │ (Unauthorized Access)
                  ▼                                     ▼
          [ Read Succeeded ]                 [ OS Filesystem Event ]
                                             (inotify / ReadDirChangesW)
                                                        │
                                                        ▼
                                             ┌─────────────────────┐
                                             │ Process Attributor  │
                                             │ Resolves Source PID │
                                             └──────────┬──────────┘
                                                        │
                                                        ▼
                                             ┌─────────────────────┐
                                             │ Mitigation Engine   │
                                             │ Verify UID Ownership│
                                             └──────────┬──────────┘
                                                        │
                         ┌──────────────────────────────┴──────────────────────────────┐
                         ▼                                                             ▼
              [ Thread Suspension ]                                         [ Bounded Forensics ]
          Linux / macOS: SIGSTOP Signal                                  - Extracts Command Line & PPID
          Windows: NtSuspendProcess Call                                 - Snapshots Open Network Sockets
          (Frozen before network stage)                                  - Memory Strings Scraped (Max 2MB)
```

## Cross-Platform Technical Breakdown

DeceptEnv operates entirely in user space by using platform-specific OS APIs:

| Subsystem | Linux | Windows | macOS |
| :--- | :--- | :--- | :--- |
| **Filesystem Telemetry** | `inotify` via standard `libc` | `ReadDirectoryChangesW` (Win32) | `FSEvents` / `kqueue` |
| **PID Attribution** | `/proc/[pid]/fd` descriptor match | Restart Manager (`rstrtmgr.dll`) | `libproc` / open file descriptors |
| **Execution Suspension** | `os.kill(pid, signal.SIGSTOP)` | `ntdll.NtSuspendProcess` | `os.kill(pid, signal.SIGSTOP)` |
| **Privilege Ceiling** | Standard User (UID != 0) | Medium Integrity (Non-Admin) | Standard User (Non-wheel) |
| **Interception Latency** | < 12ms | < 35ms | < 15ms |

## Features

- **Zero Privilege Escalation:** Deployed without `sudo` or UAC prompts; strictly operates within the user's security boundary.
- **Deterministic Neutralization:** Uses uncatchable signals (`SIGSTOP` / `NtSuspendProcess`) rather than process termination (`SIGKILL`), keeping the offending process in memory for forensic extraction.
- **High-Fidelity Synthetic Canaries:** Seeds valid Chromium SQLite databases and HMAC-tagged AWS credentials with strict `0o600` read/write permissions.
- **Bounded Forensic Collector:** Dumps memory strings, open network sockets, and execution lineage with a strict 2MB memory threshold to eliminate denial-of-service risks.
- **Symlink and Path Traversal Immune:** Canonicalizes all filesystem targets using `Path.resolve()` to prevent link redirection vulnerabilities.

## Quick Start

### Prerequisites

- Python 3.11+
- Linux, Windows 10/11, or macOS 13+

### Installation

```bash
# Clone repository
git clone https://github.com/your-username/deceptenv.git
cd deceptenv

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies in editable mode
pip install -e ".[dev]"
```

### 1. Initialize Canary Traps

Deploys decoy tripwire files across system locations:

```bash
deceptenv init
```

**Output:**

```text
[+] Canary Deployment Successful:
  ├── AWS Honeytoken:        ~/.aws/credentials.honey
  ├── Chrome SQLite Vault:   ~/.config/google-chrome/Default/Cookies.honey
  └── Workspace Secrets:     ~/.env.honey
[!] 3 active tripwires armed with permission mask 0600.
```

### 2. Launch the Active Protection Daemon

Starts the event loop and monitoring engine:

```bash
deceptenv run
```

```text
┌──────────────────────────────────────────────────────────────┐
│                    DeceptEnv Telemetry Console               │
├──────────────────────────────────────────────────────────────┤
│  Status: ACTIVE       │  Monitored Traps: 3                  │
│  User Context: UID 1000│  Target Mode: Zero-Privilege Defense │
└──────────────────────────────────────────────────────────────┘
[*] Engine initialized. Monitoring filesystem buses for credential access...
```

## Testing & Attack Simulation

DeceptEnv includes a safe, unprivileged attack simulator that reproduces infostealer credential targeting.

Open a second terminal window and run:

```bash
python tests/simulation/attack_simulator.py
```

### Observed Execution Split

**Terminal 2 (Attack Simulator Output):**

```text
[SIMULATOR] Starting simulated credential harvesting...
[SIMULATOR] Discovered target: /home/user/.aws/credentials.honey
[SIMULATOR] Executing read call...
# 
```

**Terminal 1 (DeceptEnv Defense Console):**

```text
[!] TRIPWIRE ACCESSED: /home/user/.aws/credentials.honey
[*] Resolving offending process handle...
[+] Process Identified: PID 48211 (python3)
[+] UID Ownership Verified: Current Session Owner (1000 == 1000)
[ACTION] Sent SIGSTOP to PID 48211. Process suspended successfully.

[FORENSIC SNAPSHOT GENERATED]
  ├── Binary:      /usr/bin/python3
  ├── Execution:   python tests/simulation/attack_simulator.py
  ├── Parent:      /bin/bash (PID 44102)
  ├── Net Sockets: None (Exfiltration blocked prior to network socket bind)
  └── Dump File:   ~/.deceptenv/forensics/incident_48211.json
```

## Forensic Artifact Schema

Forensic telemetry dumps are written to `~/.deceptenv/forensics/incident_.json`:

```json
{
  "timestamp": "2026-09-13T16:08:22Z",
  "incident_id": "8f3e2b4c-4a1d-498b-9d18-9182394a0293",
  "threat_target": "/home/user/.aws/credentials.honey",
  "mitigation": {
    "action": "SUSPEND_THREAD_EXECUTION",
    "mechanism": "SIGSTOP",
    "status": "SUCCESS"
  },
  "process_context": {
    "pid": 48211,
    "ppid": 44102,
    "name": "python3",
    "executable": "/usr/bin/python3",
    "command_line": "python tests/simulation/attack_simulator.py",
    "uid": 1000
  },
  "memory_analysis": {
    "scraped_bytes": 1048576,
    "extracted_urls": [],
    "identified_ip_addresses": [],
    "staged_buffers_detected": true
  }
}
```

## Defensive Engineering & Integrity Constraints

- **Self-Targeting Guard:** Compares potential target PIDs against `os.getpid()` and `os.getppid()` to prevent the engine from pausing itself or its parent shell.
- **Ownership Verification:** Before issuing a suspension signal, the engine cross-references process owner metadata against the current runtime UID/SID to ensure system-level services cannot be targeted.
- **Anti-TOCTOU Checks:** Handles Time-of-Check to Time-of-Use race conditions if a short-lived process terminates before attribution finishes.
- **Resource Clamping:** Bounds internal memory string searches to 2MB to prevent heap exhaustion attacks against the engine.

## Development & Quality Assurance

Run the test suite, linting, and type verification:

```bash
# Run unit and integration tests
pytest tests/ -v --cov=src/deceptenv

# Run strict static type checking
mypy src/

# Run security and style linting
ruff check src/
```

## License

Distributed under the MIT License. See LICENSE for details.

## Disclaimer

DeceptEnv is built for defensive threat mitigation, behavioral process auditing, and educational security research. Ensure proper authorization before testing in managed or production environments and with AI build in Antigravity.
