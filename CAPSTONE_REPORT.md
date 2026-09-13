# DeceptEnv: Defeating Infostealers via Zero-Privilege Active Mitigation

## Problem Statement

The modern cyber threat landscape is increasingly dominated by infostealers
(e.g., RedLine, Raccoon) that operate entirely within unprivileged user space.
These threats target sensitive data such as browser cookies, cryptocurrency
wallets, and cloud credentials (e.g., `~/.aws/credentials`, `.env` files).
Because these operations mimic standard user behavior and require no elevated
privileges or kernel access, they are notoriously difficult for traditional
perimeter defenses and static scanners to detect and prevent before data
exfiltration occurs.

## Literature Gap

Current Endpoint Detection and Response (EDR) solutions are built primarily for
kernel-level monitoring, process hooking, and detecting privilege escalation or
code injection. However, EDRs face a critical gap when defending against
infostealers:

1. **High Overhead:** Monitoring every standard file read (like accessing a
   cookie database) incurs massive kernel-to-user context switching overhead.
2. **False Negatives:** Infostealers execute legitimate API calls (`open()`,
   `read()`), making their behavior indistinguishable from legitimate
   applications (like an AWS CLI tool or web browser).

There is a distinct lack of lightweight, user-space active mitigation tools
that can deterministically identify and neutralize unauthorized access to
high-value targets without requiring administrative access or installing kernel
drivers.

## Methodology

DeceptEnv takes a deterministic, deception-based approach to active mitigation:

1. **Native User-Space Tripwires:** High-fidelity "honey-tokens" (synthetic
   AWS credentials, decoy Chromium SQLite databases, and `.env` files) are
   deployed in expected locations. Legitimate software will never interact with
   these specific decoys.
2. **Event-Driven Monitoring:** A low-overhead asynchronous file observer
   watches these exact tripwires using OS-native hooks, bridging into Python's
   `asyncio` event loop.
3. **OS Scheduler Suspension:** When a tripwire is triggered, the engine traces
   the offending PID. It verifies self-harm protections (ensuring the daemon or
   parent shell is not targeted) and immediately issues a `SIGSTOP` (POSIX) or
   `NtSuspendProcess` (Windows) command to halt the process execution at the
   OS scheduler level before exfiltration can complete.
4. **Bounded Forensic Capture:** Once suspended, a safe, memory-capped (max
   2MB) forensic extraction is performed, capturing the process lineage, open
   network sockets (C2 nodes), and running command lines without risking
   out-of-memory DoS.

## Results

The implementation was verified using an automated, cross-platform infostealer
simulation harness resulting in highly successful metrics:

- **Suspension Latency:** ~1.65ms (Target: < 50ms). The process is effectively
  neutralized before the file read buffer can be processed or transmitted over
  a network.
- **Resource Footprint:** ~15-18MB RAM (Target: < 25MB). CPU idle consumption
  is effectively 0% due to the asynchronous, debounced event loop.
- **Privilege Level:** Zero Privilege Requirement. Verified execution,
  detection, and suspension all successfully occur under a standard,
  non-elevated user session (`UID != 0`).
