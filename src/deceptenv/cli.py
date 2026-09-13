import asyncio
import os
import sys
from pathlib import Path

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
from deceptenv.exceptions import CanaryRegistryCorruption

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
            pass
        
        chrome_path = deployer.deploy_chrome_cookies()
        console.print(f"[green]✔[/green] Deployed Chrome Canary at {chrome_path}")
        try:
            registry.register(chrome_path)
        except CanaryRegistryCorruption:
            pass
        
        env_path = deployer.deploy_env_file()
        console.print(f"[green]✔[/green] Deployed .env Canary at {env_path}")
        try:
            registry.register(env_path)
        except CanaryRegistryCorruption:
            pass
            
        sys_path = deployer.deploy_system_config()
        console.print(f"[green]✔[/green] Deployed System Config Canary at {sys_path}")
        try:
            registry.register(sys_path)
        except CanaryRegistryCorruption:
            pass
    except Exception as e:
        console.print(f"[bold red]Failed to deploy canaries: {e}[/bold red]")

@app.command()
def list_canaries() -> None:
    """Display all active tripwires and their status."""
    config = load_config()
    
    table = Table(title="Active DeceptEnv Canaries")
    table.add_column("Path", style="cyan")
    table.add_column("Status", style="green")
    
    if config.canary_directory.exists():
        for path in config.canary_directory.rglob("*.honey"):
            table.add_row(str(path), "Active")
            
    aws_path = Path.home() / ".aws" / "credentials.honey"
    if aws_path.exists():
        table.add_row(str(aws_path), "Active")
        
    if sys.platform == "darwin":
        sys_path = Path.home() / "Library" / "Preferences" / "com.apple.deceptenv.sys.plist.honey"
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        sys_path = Path(appdata) / "Microsoft" / "Windows" / "deceptenv_config.ini.honey"
    else:
        sys_path = Path.home() / ".config" / "deceptenv" / "system.conf.honey"
        
    if sys_path.exists():
        table.add_row(str(sys_path), "Active")
        
    console.print(table)

@app.command()
def clean() -> None:
    """Safely unlink all synthetic .honey files."""
    config = load_config()
    count = 0
    
    if config.canary_directory.exists():
        for path in config.canary_directory.rglob("*.honey"):
            path.unlink(missing_ok=True)
            count += 1
            
    aws_path = Path.home() / ".aws" / "credentials.honey"
    if aws_path.exists():
        aws_path.unlink(missing_ok=True)
        count += 1
        
    if sys.platform == "darwin":
        sys_path = Path.home() / "Library" / "Preferences" / "com.apple.deceptenv.sys.plist.honey"
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        sys_path = Path(appdata) / "Microsoft" / "Windows" / "deceptenv_config.ini.honey"
    else:
        sys_path = Path.home() / ".config" / "deceptenv" / "system.conf.honey"
        
    if sys_path.exists():
        sys_path.unlink(missing_ok=True)
        count += 1
        
    console.print(f"[green]Successfully cleaned {count} canaries.[/green]")

async def async_run() -> None:
    config = load_config()
    registry = CanaryRegistry()
    
    if config.canary_directory.exists():
        for path in config.canary_directory.rglob("*.honey"):
            try:
                registry.register(path)
            except CanaryRegistryCorruption:
                pass
    aws_path = Path.home() / ".aws" / "credentials.honey"
    if aws_path.exists():
        try:
            registry.register(aws_path)
        except CanaryRegistryCorruption:
            pass
            
    if sys.platform == "darwin":
        sys_path = Path.home() / "Library" / "Preferences" / "com.apple.deceptenv.sys.plist.honey"
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        sys_path = Path(appdata) / "Microsoft" / "Windows" / "deceptenv_config.ini.honey"
    else:
        sys_path = Path.home() / ".config" / "deceptenv" / "system.conf.honey"
        
    if sys_path.exists():
        try:
            registry.register(sys_path)
        except CanaryRegistryCorruption:
            pass
        
    forensics = ForensicsExtractor(config)
    mitigator = ThreatMitigator(forensics)
    monitor = CanaryMonitor(config.canary_directory, registry)
    notifier = SlackNotifier(config)
    
    state = {
        "events": 0,
        "threats": 0,
        "last_threat": "None"
    }
    
    async def mitigation_callback(pid: int, path: Path) -> None:
        state["events"] += 1
        console.print(f"\n[bold red]ALERT: Tripwire {path} triggered by PID {pid}![/bold red]")
        report = await mitigator.freeze_threat(pid)
        if report:
            state["threats"] += 1
            state["last_threat"] = f"PID {pid}"
            console.print(f"[green]Successfully neutralized PID {pid}. Forensic snapshot saved.[/green]")
            console.print(report.model_dump_json(indent=2))
            
            # Dispatch to Slack
            await notifier.notify_incident(report, pid, path)
            
    def generate_table() -> Table:
        table = Table(title="DeceptEnv Live Telemetry")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Active Tripwires", str(len(registry._canaries)))
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

@app.command()
def run() -> None:
    """Start the active deception monitor in the foreground."""
    try:
        asyncio.run(async_run())
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down DeceptEnv.[/yellow]")

if __name__ == "__main__":
    app()
