# DeceptEnv

A high-security, defensively structured tool for deploying tripwires (canaries), monitoring file access, freezing malicious processes (mitigation), and safely extracting forensics. Designed specifically to neutralize infostealers in unprivileged user space.

<!-- Place your 30-second split-screen asciinema or OBS demo GIF here! -->
![DeceptEnv Active Mitigation Demo](demo.gif)

## IEEE Capstone Summary

For the full methodology, literature review, and performance metrics, please see the [CAPSTONE_REPORT.md](CAPSTONE_REPORT.md).
**TL;DR:** DeceptEnv neutralizes infostealers at the OS scheduler level in `< 2ms` with `0` privilege escalation required.

## Architecture

This project is built with strong security boundaries in mind:

- **Immutable Configurations**: Prevents runtime tampering using frozen data structures.
- **Strict Exceptions**: Designed to prevent sensitive data leakage via tracebacks.
- **Race-Condition Safety**: Engine logic leverages atomic OS operations to prevent TOCTOU bugs.
- **Bounded Forensics**: Strict limits on memory allocation during process dumping to prevent DoS.

## Development

```bash
pip install -e .
deceptenv --help
```
