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
| **Unit Tests** | `tests/unit/` (64 tests across canary, cli, config, engine, notifier, platform, web) | 64 passed |
| **Sandboxed E2E Tests** | `tests/simulation/test_e2e.py` (4 live process tests) | 4 passed |
| **Total Test Suite** | `pytest tests/` | **68 passed in 4.79s** |
| **Code Coverage** | `src/deceptenv` (`--cov=deceptenv`) | **67%** overall (`config.py`: 100%, `registry.py`: 100%, `notifier.py`: 94%, `monitor.py`: 91%, `forensics.py`: 87%, `mitigator.py`: 85%, `darwin.py`: 83%) |

---

## 2. Sandboxed Attacker Neutralization Proof

### A. Live E2E Monitor + Mitigator Benchmark (`tests/simulation/test_e2e.py`)

Each simulation spawns a real subprocess inside an isolated `pytest` `tmp_path` sandbox:

1. `test_end_to_end_neutralization` — Subprocess reads `credentials.honey`; `CanaryMonitor` detects `st_atime` transition, `DarwinAdapter` attributes caller PID, and `ThreatMitigator` issues `SIGSTOP` (`psutil.Process.status() == STATUS_STOPPED`). **PASSED**
2. `test_negative_unrelated_file` — Subprocess reads non-canary `normal_file.txt`; engine ignores event and does not freeze process. **PASSED**
3. `test_end_to_end_latency_benchmark` — End-to-end latency from process spawn to scheduler suspension (`SIGSTOP`): **170.89 ms** (<200 ms SLA). **PASSED**
4. `test_sandboxed_attacker_exfiltration_blocked_with_forensics` — Subprocess infostealer (`attacker_payload.py`) reads `.env.honey`, engine freezes PID in scheduler (`STATUS_STOPPED`), extracts `ForensicReport` with process lineage, and blocks `EXFILTRATION_SUCCEEDED` output. **PASSED**

### B. Standalone Live Attacker Simulator (`tests/simulation/attack_simulator.py`)

Executed in isolated temporary sandbox (`/var/folders/.../deceptenv_sim_*`):

```text
[*] Deployed AWS canary at .../canaries/credentials.honey
[*] Spawning infostealer child process...
[*] Attributed threat to PID 3937. Initiating freeze...
Successfully suspended threat process: PID 3937
[+] Forensic Report Extracted:
{
  "lineage": [
    {
      "pid": 3937,
      "ppid": 3936,
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
[+] Process suspended in 1.25ms
[*] Waiting 6 seconds to verify it never finishes the sleep...
[+] SUCCESS: Infostealer simulation completely neutralized.
```

---

## 3. Zero-Privilege Sandbox Canary Deployment Proof

Verified under Seatbelt sandbox where `~/Library/Application Support/Google/Chrome/Default` and `~/.aws` deny write access (`PermissionError`):

- `deceptenv init` gracefully falls back to `DECEPTENV_CANARY_DIR` and deploys all 4 tripwires (`credentials.honey`, `Cookies.honey`, `.env.honey`, `com.apple.deceptenv.sys.plist.honey`) with `0o600` permissions.
- `deceptenv list-canaries` lists all 4 deployed targets as `Active`.
- Web Dashboard `get_canary_list()` reports all 4 targets with `"status": "ARMED"` and SHA-256 signatures.
- `deceptenv clean` cleanly unlinks all 4 decoys.
