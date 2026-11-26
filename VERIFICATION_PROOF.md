# DeceptEnv — Verification & Sandboxed Attacker Proof

- **Repository:** `https://github.com/SURYA16-T/DeceptEnv`
- **Version:** `0.1.0`
- **License:** MIT ([LICENSE](./LICENSE))
- **Verified Environment:** macOS (`Darwin arm64`), Python `3.9.6`, Seatbelt Sandbox

---

## 1. Static Analysis & Unit/E2E Test Suite Proof

Executed inside an unprivileged sandbox:

```bash
ruff check src/ tests/
mypy src/ --ignore-missing-imports
pytest tests/ -v -s --cov=deceptenv --cov-report=term-missing --tb=short
```

### Observed Results

| Check | Scope | Result |
| :--- | :--- | :--- |
| **Ruff Lint** | `src/` and `tests/` (`E`, `F`, `B`, `S`, `I`) | Passed (0 issues) |
| **Mypy Strict** | 18 source files (`strict = true`) | Passed (0 issues) |
| **Unit Tests** | `tests/unit/` (70 tests across canary, cli, config, engine, notifier, platform, web) | **70 passed** |
| **Sandboxed E2E Tests** | `tests/simulation/test_e2e.py` (4 live real-read process tests) | **4 passed** |
| **Total Test Suite** | `pytest tests/` | **74 passed in 3.60s** |
| **Code Coverage** | `src/deceptenv` (`--cov=deceptenv`) | **66%** overall (`config.py`: 100%, `registry.py`: 100%, `notifier.py`: 94%, `forensics.py`: 92%, `monitor.py`: 90%, `mitigator.py`: 86%, `darwin.py`: 84%) |

---

## 2. Genuine Real-Read Sandboxed Attacker Prevention Proof

### A. Real-Read E2E Monitor + Mitigator Suite (`tests/simulation/test_e2e.py`)

Each test spawns real child processes that perform genuine file reads (`open(...).read()`, with no `os.utime()` helper in the attacker):

1. `test_end_to_end_neutralization` — Child process reads `credentials.honey`; `CanaryMonitor` detects APFS `st_atime_ns` advance via `st_atime < st_mtime` arming, `DarwinAdapter` attributes PID, and `ThreatMitigator` freezes it (`STATUS_STOPPED`). **PASSED**
2. `test_negative_unrelated_file` — Child process reads non-canary `normal_file.txt`; monitor ignores access and process continues uninterrupted. **PASSED**
3. `test_end_to_end_latency_benchmark` — End-to-end real-read latency from spawn to scheduler suspension (`SIGSTOP`): **172.09 ms** (<200 ms SLA). **PASSED**
4. `test_sandboxed_attacker_exfiltration_blocked_with_forensics` — Infostealer subprocess reads `.env.honey`, gets frozen (`STATUS_STOPPED`), yields `ForensicReport` lineage, blocks `"EXFILTRATION_SUCCEEDED"`, and a second consecutive attacker process is also intercepted and frozen via monitor re-arming. **PASSED**

### B. Full Pipeline Live Attacker Simulator (`tests/simulation/attack_simulator.py`)

Executed in isolated temporary sandbox (`/var/folders/.../deceptenv_sim_*`):

```text
[*] Deployed sandbox canary: .../canaries/.env.honey (mode=0o600, sha256=3e256bf3eb823a22...)
[*] Spawning real unmodified infostealer child process...
[*] Monitor intercepted read on .env.honey -> froze PID 4878
[+] Scheduler State Verified: PID 4878 status='stopped' (SIGSTOP)
[+] Mitigation Freeze Latency: 1.38ms (E2E spawn->frozen: 68.38ms)
[+] Forensic Report Extracted:
{
  "lineage": [
    {
      "pid": 4878,
      "ppid": 4877,
      "name": "Python",
      "cmdline": [".../Python", ".../rogue_stealer.py"]
    },
    ...
  ],
  "network_sockets": [],
  "extracted_urls": [],
  "extracted_ips": [],
  "extracted_base64": []
}
[*] Verifying frozen process remains suspended for 2s...
[+] Freeze Persistence Verified: proc.poll()=None (still frozen)
[+] Exfiltration Blocked: 'Exfiltration Complete' never reached.
[+] SUCCESS: Real-read infostealer simulation completely neutralized.
```

---

## 3. Prevention & Hardening Regression Proofs

- **Symlink Overwrite Prevention (`test_canary_deployer_rejects_symlink_targets`):** `CanaryDeployer` rejects symlink canary targets (`SecurityBoundaryViolation`) before touching victim files.
- **Atomic `0o600` SQLite Canary Creation (`deploy_chrome_cookies`):** Populates SQLite database in a private `0o600` temporary file and swaps atomically via `os.replace()`.
- **Self/Shell/Ancestor Guard (`test_mitigator_blocks_ancestor_pid`):** `ThreatMitigator` rejects self PID, `ppid`, and full ancestor lineage, plus lazily creates `asyncio.Lock` safely on Python 3.9 sync initialization.
- **Tier 2 Heuristic Exclusion (`test_darwin_tier2_skips_stopped_processes`):** Skips `STATUS_STOPPED`/`STATUS_ZOMBIE` and ancestor PIDs so frozen threats never mask new processes.
- **Forensic Memory & C2 URL Extraction (`test_forensics_capture_snapshot_extracts_iocs`):** Skips kernel `[vvar]`/`[vdso]`/`[vsyscall]` pages, isolates per-region read errors, and extracts full HTTP(S) URLs with paths and query parameters (`https://evil-c2.example/exfil?id=1`), IPv4s, and Base64 payloads.
