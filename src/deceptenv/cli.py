import asyncio
from pathlib import Path
from typing import Any, Dict

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import load_config
from deceptenv.engine.forensics import ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.engine.monitor import CanaryMonitor
from deceptenv.engine.notifier import SlackNotifier
from deceptenv.exceptions import CanaryRegistryCorruption, OSPrimitiveError

app = typer.Typer(help="DeceptEnv: Active Deception Engine")
console = Console()


@app.command()
def init() -> None:
    """Deploy canary files across target paths."""
    config = load_config()
    deployer = CanaryDeployer(config.canary_directory)
    registry = CanaryRegistry()

    console.print("[bold blue]Deploying synthetic canaries...[/bold blue]")
    try:
        aws_path = deployer.deploy_aws_credentials()
        console.print(f"[green]✔[/green] Deployed AWS Canary at {aws_path}")
        try:
            registry.register(aws_path)
        except CanaryRegistryCorruption:
            pass  # Already registered; safe to continue

        chrome_path = deployer.deploy_chrome_cookies()
        console.print(f"[green]✔[/green] Deployed Chrome Canary at {chrome_path}")
        try:
            registry.register(chrome_path)
        except CanaryRegistryCorruption:
            pass  # Already registered; safe to continue

        env_path = deployer.deploy_env_file()
        console.print(f"[green]✔[/green] Deployed .env Canary at {env_path}")
        try:
            registry.register(env_path)
        except CanaryRegistryCorruption:
            pass  # Already registered; safe to continue

        sys_path = deployer.deploy_system_config()
        console.print(f"[green]✔[/green] Deployed System Config Canary at {sys_path}")
        try:
            registry.register(sys_path)
        except CanaryRegistryCorruption:
            pass  # Already registered; safe to continue
    except Exception as e:
        console.print(f"[bold red]Failed to deploy canaries: {e}[/bold red]")


def _safe_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _safe_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _safe_glob(path: Path, pattern: str) -> list[Path]:
    try:
        if not path.exists():
            return []
        return [p for p in path.glob(pattern) if _safe_is_file(p)]
    except OSError:
        return []


def _safe_rglob(path: Path, pattern: str) -> list[Path]:
    try:
        if not path.exists():
            return []
        return [p for p in path.rglob(pattern) if _safe_is_file(p)]
    except OSError:
        return []


@app.command()
def list_canaries() -> None:
    """Display all active tripwires and their status."""
    config = load_config()

    table = Table(title="Active DeceptEnv Canaries")
    table.add_column("Path", style="cyan")
    table.add_column("Status", style="green")

    found_paths: set[Path] = set()

    for path in _safe_rglob(config.canary_directory, "*.honey*"):
        if path not in found_paths:
            found_paths.add(path)
            table.add_row(str(path), "Active")

    aws_path = CanaryDeployer.get_aws_credentials_path(config.canary_directory)
    for p in _safe_glob(aws_path.parent, "credentials.honey*"):
        if p not in found_paths:
            found_paths.add(p)
            table.add_row(str(p), "Active")

    chrome_path = CanaryDeployer.get_chrome_cookies_path(config.canary_directory)
    for p in _safe_glob(chrome_path.parent, "Cookies.honey*"):
        if p not in found_paths:
            found_paths.add(p)
            table.add_row(str(p), "Active")

    sys_path = CanaryDeployer.get_system_config_path(config.canary_directory)
    if _safe_exists(sys_path) and sys_path not in found_paths:
        found_paths.add(sys_path)
        table.add_row(str(sys_path), "Active")

    console.print(table)


@app.command()
def clean() -> None:
    """Safely unlink all synthetic .honey files."""
    config = load_config()
    count = 0
    cleaned_paths: set[Path] = set()

    for path in _safe_rglob(config.canary_directory, "*.honey*"):
        if path not in cleaned_paths:
            try:
                path.unlink(missing_ok=True)
                cleaned_paths.add(path)
                count += 1
            except OSError:
                pass

    aws_path = CanaryDeployer.get_aws_credentials_path(config.canary_directory)
    for path in _safe_glob(aws_path.parent, "credentials.honey*"):
        if path not in cleaned_paths:
            try:
                path.unlink(missing_ok=True)
                cleaned_paths.add(path)
                count += 1
            except OSError:
                pass

    chrome_path = CanaryDeployer.get_chrome_cookies_path(config.canary_directory)
    for path in _safe_glob(chrome_path.parent, "Cookies.honey*"):
        if path not in cleaned_paths:
            try:
                path.unlink(missing_ok=True)
                cleaned_paths.add(path)
                count += 1
            except OSError:
                pass

    sys_path = CanaryDeployer.get_system_config_path(config.canary_directory)
    if _safe_exists(sys_path) and sys_path not in cleaned_paths:
        try:
            sys_path.unlink(missing_ok=True)
            cleaned_paths.add(sys_path)
            count += 1
        except OSError:
            pass

    console.print(f"[green]Successfully cleaned {count} canaries.[/green]")


async def async_run() -> None:
    config = load_config()
    registry = CanaryRegistry()

    def try_register(path: Path) -> None:
        try:
            registry.register(path)
        except (CanaryRegistryCorruption, OSError):
            pass  # Already registered or inaccessible; safe to continue

    for path in _safe_rglob(config.canary_directory, "*.honey*"):
        try_register(path)

    aws_path = CanaryDeployer.get_aws_credentials_path(config.canary_directory)
    if _safe_exists(aws_path):
        try_register(aws_path)

    chrome_path = CanaryDeployer.get_chrome_cookies_path(config.canary_directory)
    if _safe_exists(chrome_path):
        try_register(chrome_path)

    sys_path = CanaryDeployer.get_system_config_path(config.canary_directory)
    if _safe_exists(sys_path):
        try_register(sys_path)

    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    monitor = CanaryMonitor(config.canary_directory, registry)
    notifier = SlackNotifier(config)

    state: Dict[str, Any] = {
        "events": 0,
        "threats": 0,
        "last_threat": "None",
    }

    async def mitigation_callback(pid: int, path: Path) -> None:
        state["events"] += 1
        console.print(
            f"\n[bold red]ALERT: Tripwire {path} triggered by PID {pid}![/bold red]"
        )
        try:
            report = await mitigator.freeze_threat(pid)
        except OSPrimitiveError as e:
            console.print(f"[bold red]Mitigation error for PID {pid}: {e}[/bold red]")
            return

        if report:
            state["threats"] += 1
            state["last_threat"] = f"PID {pid}"
            console.print(
                f"[green]Successfully neutralized PID {pid}. Forensic snapshot saved.[/green]"
            )
            console.print(report.model_dump_json(indent=2))

            # Dispatch to Slack
            await notifier.notify_incident(report, pid, path)

    def generate_table() -> Table:
        table = Table(title="DeceptEnv Live Telemetry")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Active Tripwires", str(len(registry.get_all_paths())))
        table.add_row("Events Processed", str(state["events"]))
        table.add_row("Threats Neutralized", str(state["threats"]))
        table.add_row("Last Threat", state["last_threat"])
        return table

    async def render_ui() -> None:
        with Live(generate_table(), refresh_per_second=4) as live:
            while True:
                await asyncio.sleep(0.5)
                live.update(generate_table())

    ui_task = asyncio.create_task(render_ui())
    monitor_task = asyncio.create_task(monitor.start(mitigation_callback))

    try:
        await asyncio.gather(ui_task, monitor_task)
    except asyncio.CancelledError:
        pass
    finally:
        ui_task.cancel()
        monitor_task.cancel()
        await asyncio.gather(ui_task, monitor_task, return_exceptions=True)


@app.command()
def run() -> None:
    """Start the active deception monitor in the foreground."""
    try:
        asyncio.run(async_run())
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down DeceptEnv.[/yellow]")


@app.command()
def dashboard(port: int = 8080) -> None:
    """Launch the real-time visual web dashboard at http://localhost:PORT."""
    from deceptenv.web import start_server

    console.print(f"[bold green]Starting DeceptEnv Web Dashboard on http://localhost:{port}[/bold green]")
    start_server(port)


if __name__ == "__main__":
    app()

