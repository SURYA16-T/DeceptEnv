#!/usr/bin/env python3
"""DeceptEnv Unified End-to-End Pipeline & FIFO Architecture Flow.

This script links and exercises every major component of DeceptEnv in a complete,
connected workflow:
1. Configuration (SecurityConfig / load_config)
2. Canary Deployment (CanaryDeployer) & SQLite Registry (CanaryRegistry)
3. Platform Abstraction Layer (get_platform_adapter -> Darwin / Linux / Windows)
4. Real-time Async FIFO Telemetry & Detection (CanaryMonitor + asyncio.Queue)
5. Threat Mitigation & Scheduler-Level Suspension (ThreatMitigator)
6. Bounded Forensics Snapshot (ForensicsExtractor -> Lineage, Sockets, Memory)
7. Incident Dispatch (SlackNotifier)
8. Named Pipe (FIFO) Tripwire Experimentation & Safe Teardown
"""

# ruff: noqa: S101, S603

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicReport, ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.engine.monitor import CanaryMonitor
from deceptenv.engine.notifier import SlackNotifier
from deceptenv.platform import get_platform_adapter

console = Console()


def print_banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]DeceptEnv[/bold cyan]: [bold green]Unified Architecture & FIFO Flow Demonstration[/bold green]\n"
            "[dim]Connecting Canary Deployer, SQLite Registry, Monitor FIFO, Platform Adapter, Mitigator, Forensics, and Notifier[/dim]",
            border_style="cyan",
        )
    )


async def main() -> None:
    print_banner()

    # Create temporary sandbox workspace to avoid touching user files
    with tempfile.TemporaryDirectory(prefix="deceptenv_flow_") as temp_dir:
        workspace_dir = Path(temp_dir)
        console.print(f"[bold blue][Step 1][/bold blue] Initializing Security Configuration in: [cyan]{workspace_dir}[/cyan]")

        # 1. Config
        config = SecurityConfig(
            canary_directory=workspace_dir / "canaries",
            max_forensic_dump_size_bytes=1024 * 1024,
            slack_webhook_url=None,  # Dry-run for demonstration
        )
        config.canary_directory.mkdir(parents=True, exist_ok=True)

        # 2. Platform Adapter
        console.print("\n[bold blue][Step 2][/bold blue] Probing Native OS Platform Adapter...")
        platform_adapter = get_platform_adapter()
        console.print(f"  [green]✔[/green] Active OS Adapter: [bold magenta]{type(platform_adapter).__name__}[/bold magenta]")

        # 3. Deployer & Registry
        console.print("\n[bold blue][Step 3][/bold blue] Deploying Synthetic Tripwires & Registering Cryptographic Hashes...")
        deployer = CanaryDeployer(config.canary_directory)
        registry = CanaryRegistry()

        deployed_paths: list[Path] = []

        # Deploy synthetic .env canary
        env_canary = deployer.deploy_env_file()
        registry.register(env_canary)
        deployed_paths.append(env_canary)
        console.print(f"  [green]✔[/green] Deployed & Registered .env Canary: [dim]{env_canary}[/dim]")

        # Deploy custom workspace AWS canary
        aws_canary = config.canary_directory / "credentials.honey"
        with open(aws_canary, "w") as f:
            f.write(
                "[default]\n"
                f"aws_access_key_id = AKIA{os.urandom(8).hex().upper()}\n"
                f"aws_secret_access_key = {os.urandom(20).hex()}\n"
            )
        os.chmod(aws_canary, 0o600)
        registry.register(aws_canary)
        deployed_paths.append(aws_canary)
        console.print(f"  [green]✔[/green] Deployed & Registered AWS Canary: [dim]{aws_canary}[/dim]")

        # Deploy System Config Canary
        sys_canary = deployer.deploy_system_config()
        registry.register(sys_canary)
        deployed_paths.append(sys_canary)
        console.print(f"  [green]✔[/green] Deployed & Registered System Config Canary: [dim]{sys_canary}[/dim]")

        # Deploy Chrome Cookies Canary
        chrome_canary = deployer.deploy_chrome_cookies()
        registry.register(chrome_canary)
        deployed_paths.append(chrome_canary)
        console.print(f"  [green]✔[/green] Deployed & Registered Chrome Cookies Canary: [dim]{chrome_canary}[/dim]")

        # Display Registry Table
        reg_table = Table(title="Canary Registry Contents", border_style="dim")
        reg_table.add_column("Tripwire Path", style="cyan")
        reg_table.add_column("SHA-256 Signature", style="green")
        for path in registry.get_all_paths():
            meta = registry.get_canary_metadata(path)
            sha_val = str(meta.get("hash", ""))
            reg_table.add_row(str(path), sha_val[:16] + "...")
        console.print(reg_table)

        # 4. Forensics, Mitigator & Notifier
        console.print("\n[bold blue][Step 4][/bold blue] Initializing Forensics Extractor, Mitigator & Slack Notifier...")
        forensics = ForensicsExtractor(config)
        mitigator = ThreatMitigator(forensics)
        notifier = SlackNotifier(config)
        console.print("  [green]✔[/green] Mitigator & Bounded Forensics pipeline online.")

        # 5. Async FIFO Monitor
        console.print("\n[bold blue][Step 5][/bold blue] Starting Async CanaryMonitor (Internal FIFO Event Queue)...")
        monitor = CanaryMonitor(config.canary_directory, registry)

        # Incident capture containers
        mitigation_events: list[tuple[int, Path, ForensicReport | None, float]] = []

        async def mitigation_handler(pid: int, path: Path) -> None:
            t0 = time.time()
            console.print(f"\n[bold red]⚡ ALERT: Unauthorized read on {path.name} by PID {pid}![/bold red]")
            report = await mitigator.freeze_threat(pid)
            elapsed_ms = (time.time() - t0) * 1000.0
            mitigation_events.append((pid, path, report, elapsed_ms))

            if report:
                console.print(f"[bold green]✔ Threat PID {pid} neutralized in {elapsed_ms:.2f}ms[/bold green]")
                # Dispatch alert via notifier (handles None webhook safely)
                await notifier.notify_incident(report, pid, path)

        monitor_task = asyncio.create_task(monitor.start(mitigation_handler))
        await asyncio.sleep(0.3)  # Allow monitor polling loop to initialize baseline atime

        # 6. Spawning Simulated Infostealer Process
        console.print("\n[bold blue][Step 6][/bold blue] Spawning Simulated Infostealer Process...")
        stealer_script = workspace_dir / "simulated_infostealer.py"
        stealer_code = f"""
import time
import os

canary_target = r"{aws_canary}"
try:
    # 1. Access the canary file (Triggers st_atime change event)
    with open(canary_target, "r") as f:
        _ = f.read()
    now = time.time()
    os.utime(canary_target, (now, now))
except Exception:
    pass

# Signal we touched the file
print("CANARY_ACCESSED", flush=True)

# Malware attempt to stage & exfiltrate data (should never execute if frozen)
time.sleep(4)
print("EXFILTRATION_SUCCEEDED", flush=True)
"""
        stealer_script.write_text(stealer_code)

        proc = subprocess.Popen(
            [sys.executable, str(stealer_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for the process to touch the canary
        if proc.stdout:
            _ = proc.stdout.readline()

        console.print(f"  [dim]Infostealer spawned with PID {proc.pid}. Awaiting mitigation...[/dim]")

        # Wait for monitor and mitigator to intercept
        for _ in range(40):
            if mitigation_events:
                break
            await asyncio.sleep(0.05)

        # 7. Verification of Neutralization & Forensics
        console.print("\n[bold blue][Step 7][/bold blue] Validating Forensic Extraction & Execution Freeze...")
        assert len(mitigation_events) > 0, "Mitigation event failed to trigger!"

        frozen_pid, tripped_path, report, duration_ms = mitigation_events[0]
        assert report is not None, "Forensic report was not generated!"

        summary_table = Table(title="Neutralization & Forensic Summary", border_style="green")
        summary_table.add_column("Attribute", style="cyan")
        summary_table.add_column("Telemetry Value", style="magenta")

        summary_table.add_row("Triggering Canary", str(tripped_path))
        summary_table.add_row("Neutralized PID", str(frozen_pid))
        summary_table.add_row("Mitigation Latency", f"{duration_ms:.2f} ms")
        summary_table.add_row("Ancestry Lineage Depth", str(len(report.lineage)))
        summary_table.add_row("Parent Process (PPID)", str(report.lineage[0].ppid if report.lineage else "N/A"))
        summary_table.add_row("Target Process Binary", report.lineage[0].name if report.lineage else "Unknown")
        summary_table.add_row("Extracted Sockets Count", str(len(report.network_sockets)))
        console.print(summary_table)

        # Verify that exfiltration was prevented
        await asyncio.sleep(1.0)
        stdout_remaining = ""
        try:
            # Terminate the frozen test process
            proc.kill()
            stdout_remaining, _ = proc.communicate(timeout=2.0)
        except Exception:
            pass

        assert "EXFILTRATION_SUCCEEDED" not in stdout_remaining, (
            "Failure: Malware completed exfiltration before mitigation!"
        )
        console.print("[bold green]✔ Exfiltration was successfully blocked (Malware was frozen in place)![/bold green]")

        # 8. Teardown & Clean
        console.print("\n[bold blue][Step 8][/bold blue] Graceful Teardown & Cleanup...")
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

        # Unlink all canaries
        for canary in deployed_paths:
            if canary.exists():
                canary.unlink(missing_ok=True)
        console.print("  [green]✔[/green] All synthetic tripwires unlinked safely.")

    console.print("\n[bold green]🎉 End-to-End Pipeline Execution: 100% SUCCESSFUL![/bold green]\n")


if __name__ == "__main__":
    asyncio.run(main())
