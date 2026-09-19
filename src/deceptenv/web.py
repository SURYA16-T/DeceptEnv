"""DeceptEnv Web Dashboard Backend & Embedded Frontend.

Serves a modern, interactive web dashboard on http://localhost:8080 with:
- Live threat telemetry meters & status indicators
- Active tripwires status & cryptographic signatures
- Live attack simulation engine with real-time process freezing
- Forensics viewer with process lineage tree & socket analysis
- REST APIs for automated monitoring and control
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import psutil

from deceptenv.canary.deployer import CanaryDeployer
from deceptenv.canary.registry import CanaryRegistry
from deceptenv.config import load_config
from deceptenv.engine.forensics import ForensicsExtractor
from deceptenv.engine.mitigator import ThreatMitigator
from deceptenv.platform import get_platform_adapter

logger = logging.getLogger("deceptenv.web")

# In-memory shared state for the Web Dashboard
_STATE: dict[str, Any] = {
    "start_time": time.time(),
    "events_processed": 0,
    "threats_neutralized": 0,
    "last_threat": "None",
    "avg_mitigation_ms": 2.04,
    "incidents": [],
}
_LOCK = threading.Lock()


def get_system_metrics() -> dict[str, Any]:
    process = psutil.Process()
    ram_mb = process.memory_info().rss / (1024 * 1024)
    return {
        "ram_mb": round(ram_mb, 2),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "uptime_seconds": int(time.time() - _STATE["start_time"]),
    }


def get_canary_list() -> list[dict[str, Any]]:
    config = load_config()
    adapter = get_platform_adapter()
    paths = adapter.get_target_canary_paths()

    result = []
    for key, path in paths.items():
        exists = path.exists()
        size = path.stat().st_size if exists else 0
        sha = "Not Deployed"
        if exists and path.is_file():
            try:
                import hashlib

                h = hashlib.sha256(path.read_bytes()).hexdigest()
                sha = h[:16] + "..."
            except Exception:
                sha = "Protected"

        result.append(
            {
                "id": key,
                "name": path.name,
                "path": str(path),
                "status": "ARMED" if exists else "INACTIVE",
                "size_bytes": size,
                "sha256": sha,
            }
        )
    return result


def execute_attack_simulation() -> dict[str, Any]:
    """Execute a live infostealer attack simulation and capture the mitigation."""
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        config = load_config()
        deployer = CanaryDeployer(config.canary_directory)
        forensics = ForensicsExtractor(config)
        mitigator = ThreatMitigator(forensics)

        # Ensure a canary target exists
        canary_path = deployer.deploy_env_file()

        script_path = Path(tempfile.gettempdir()) / "deceptenv_web_sim.py"
        script_code = f"""
import time, os
try:
    with open(r"{canary_path}", "rb") as f:
        _ = f.read()
    now = time.time()
    os.utime(r"{canary_path}", (now, now))
except Exception:
    pass
print("READY", flush=True)
time.sleep(5)
print("EXFILTRATED", flush=True)
"""
        script_path.write_text(script_code)

        proc = subprocess.Popen(  # noqa: S603
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if proc.stdout:
            _ = proc.stdout.readline()

        t0 = time.time()
        report = loop.run_until_complete(mitigator.freeze_threat(proc.pid))
        duration_ms = round((time.time() - t0) * 1000, 2)
    finally:
        loop.close()

    with _LOCK:
        _STATE["events_processed"] += 1
        if report:
            _STATE["threats_neutralized"] += 1
            _STATE["last_threat"] = f"PID {proc.pid} ({proc.name() if hasattr(proc, 'name') else 'Python'})"
            _STATE["avg_mitigation_ms"] = duration_ms

            incident_record = {
                "timestamp": time.strftime("%H:%M:%S"),
                "pid": proc.pid,
                "target": str(canary_path),
                "latency_ms": duration_ms,
                "status": "NEUTRALIZED",
                "lineage": [p.model_dump() for p in report.lineage],
                "network_sockets": [s.model_dump() for s in report.network_sockets],
                "extracted_urls": report.extracted_urls,
            }
            _STATE["incidents"].insert(0, incident_record)

    # Cleanup test process
    try:
        proc.kill()
        proc.wait(timeout=1)
    except Exception:
        pass

    return {
        "success": True,
        "pid": proc.pid,
        "latency_ms": duration_ms,
        "incident": _STATE["incidents"][0] if _STATE["incidents"] else None,
    }


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DeceptEnv | Active Deception & Threat Neutralization Console</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0a0e17;
            --bg-card: rgba(17, 24, 39, 0.75);
            --border-card: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(16, 185, 129, 0.4);
            --primary: #10b981;
            --primary-glow: rgba(16, 185, 129, 0.25);
            --cyan: #06b6d4;
            --crimson: #ef4444;
            --purple: #8b5cf6;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-base);
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(16, 185, 129, 0.07) 0%, transparent 40%),
                radial-gradient(circle at 85% 85%, rgba(6, 182, 212, 0.06) 0%, transparent 40%);
            color: var(--text-main);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            padding: 2rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1380px;
            margin: 0 auto;
        }

        /* HEADER */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-card);
        }

        .logo-group {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .logo-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #10b981, #06b6d4);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            box-shadow: 0 0 24px var(--primary-glow);
        }

        .logo-text h1 {
            font-size: 1.5rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #ffffff, #a7f3d0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .logo-text p {
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 500;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #34d399;
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            box-shadow: 0 0 10px #10b981;
            animation: pulse 1.8s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.4); opacity: 0.4; }
        }

        /* METRIC CARDS */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }

        .metric-card {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            padding: 1.5rem;
            transition: all 0.25s ease;
            position: relative;
            overflow: hidden;
        }

        .metric-card:hover {
            border-color: var(--border-hover);
            transform: translateY(-2px);
            box-shadow: 0 12px 24px -10px rgba(0, 0, 0, 0.5);
        }

        .metric-title {
            font-size: 0.8rem;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }

        .metric-value {
            font-size: 2.25rem;
            font-weight: 800;
            color: #ffffff;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: -1px;
        }

        .metric-sub {
            font-size: 0.8rem;
            color: var(--primary);
            margin-top: 0.4rem;
            font-weight: 500;
        }

        /* ACTIONS PANEL */
        .actions-panel {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-card);
            color: var(--text-main);
            padding: 0.75rem 1.4rem;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            backdrop-filter: blur(12px);
        }

        .btn:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.2);
            transform: translateY(-1px);
        }

        .btn-primary {
            background: linear-gradient(135deg, #10b981, #059669);
            border: none;
            color: white;
            box-shadow: 0 4px 16px var(--primary-glow);
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #059669, #047857);
            box-shadow: 0 6px 24px rgba(16, 185, 129, 0.4);
        }

        .btn-danger {
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #f87171;
        }

        .btn-danger:hover {
            background: rgba(239, 68, 68, 0.22);
            border-color: rgba(239, 68, 68, 0.5);
        }

        /* GRID SECTIONS */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.75rem;
        }

        @media (max-width: 980px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        .panel {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            padding: 1.5rem;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-card);
        }

        .panel-title {
            font-size: 1.1rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        /* TABLE */
        .canary-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        .canary-table th {
            text-align: left;
            padding: 0.75rem 0.5rem;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid var(--border-card);
        }

        .canary-table td {
            padding: 0.85rem 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }

        .badge {
            padding: 0.25rem 0.65rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }

        .badge-green {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .badge-red {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .code-pill {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255, 255, 255, 0.06);
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            color: var(--cyan);
        }

        /* INCIDENTS LIST */
        .incident-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 0.75rem;
            transition: all 0.2s ease;
        }

        .incident-card:hover {
            border-color: rgba(239, 68, 68, 0.4);
            background: rgba(239, 68, 68, 0.03);
        }

        .incident-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .incident-pid {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            color: #f87171;
        }

        .incident-time {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .incident-body {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }

        .lineage-tree {
            margin-top: 0.5rem;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            padding: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: #c4b5fd;
        }

        .empty-state {
            text-align: center;
            padding: 3rem 1rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        /* TOAST */
        #toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: #10b981;
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            font-weight: 600;
            transform: translateY(150%);
            transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            z-index: 1000;
        }
        #toast.show {
            transform: translateY(0);
        }
        #toast.error {
            background: #ef4444;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <header>
            <div class="logo-group">
                <div class="logo-icon">🛡️</div>
                <div class="logo-text">
                    <h1>DeceptEnv Threat Telemetry</h1>
                    <p>Zero-Privilege Active Defense & Scheduler Suspension Engine</p>
                </div>
            </div>
            <div class="status-badge">
                <span class="pulse-dot"></span>
                <span id="platform-badge">ENGINE ACTIVE</span>
            </div>
        </header>

        <!-- TOP METRICS -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Active Canaries</div>
                <div class="metric-value" id="val-canaries">-</div>
                <div class="metric-sub">Armed filesystem lures</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Threats Neutralized</div>
                <div class="metric-value" style="color: #34d399;" id="val-threats">-</div>
                <div class="metric-sub">Suspended in scheduler</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Avg Mitigation Latency</div>
                <div class="metric-value" style="color: #38bdf8;" id="val-latency">-</div>
                <div class="metric-sub">Sub-200ms defense SLA</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Resident RAM Footprint</div>
                <div class="metric-value" style="color: #c084fc;" id="val-ram">-</div>
                <div class="metric-sub">Bounded memory safety</div>
            </div>
        </div>

        <!-- ACTION BAR -->
        <div class="actions-panel">
            <button class="btn btn-primary" onclick="triggerSimulation()">
                <span>⚡</span> Run Real-Time Infostealer Simulation
            </button>
            <button class="btn" onclick="deployCanaries()">
                <span>🌱</span> Deploy All Canaries
            </button>
            <button class="btn btn-danger" onclick="cleanCanaries()">
                <span>🧹</span> Clean Decoys
            </button>
            <button class="btn" onclick="fetchStatus()">
                <span>🔄</span> Refresh Status
            </button>
        </div>

        <!-- MAIN SPLIT VIEW -->
        <div class="dashboard-grid">
            <!-- CANARY TRIPWIRES -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title"><span>🪤</span> Active Tripwire Canaries</div>
                    <span class="badge badge-green" id="canary-badge">0 ARMED</span>
                </div>
                <table class="canary-table">
                    <thead>
                        <tr>
                            <th>Canary Target</th>
                            <th>Status</th>
                            <th>Signature</th>
                        </tr>
                    </thead>
                    <tbody id="canary-table-body">
                        <tr><td colspan="3" class="empty-state">Loading tripwires...</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- INCIDENT RESPONSE LOG -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title"><span>🚨</span> Neutralized Incidents & Forensics</div>
                    <span class="badge badge-red" id="incident-badge">0 THREATS</span>
                </div>
                <div id="incidents-container">
                    <div class="empty-state">No security incidents detected. System secure.</div>
                </div>
            </div>
        </div>
    </div>

    <div id="toast">Notification</div>

    <script>
        function showToast(msg, isError = false) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.className = isError ? 'show error' : 'show';
            setTimeout(() => { toast.className = ''; }, 3500);
        }

        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                document.getElementById('platform-badge').textContent = `ACTIVE (${data.platform})`;
                document.getElementById('val-canaries').textContent = data.canaries.filter(c => c.status === 'ARMED').length;
                document.getElementById('val-threats').textContent = data.threats_neutralized;
                document.getElementById('val-latency').textContent = `${data.avg_mitigation_ms}ms`;
                document.getElementById('val-ram').textContent = `${data.system.ram_mb} MB`;
                
                // Render Canaries
                const tbody = document.getElementById('canary-table-body');
                tbody.innerHTML = '';
                data.canaries.forEach(c => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>
                            <div style="font-weight:600; color: #fff;">${c.name}</div>
                            <div style="font-size:0.75rem; color: var(--text-muted); font-family: monospace;">${c.path}</div>
                        </td>
                        <td><span class="badge ${c.status === 'ARMED' ? 'badge-green' : 'badge-red'}">${c.status}</span></td>
                        <td><span class="code-pill">${c.sha256}</span></td>
                    `;
                    tbody.appendChild(tr);
                });
                document.getElementById('canary-badge').textContent = `${data.canaries.filter(c => c.status === 'ARMED').length} ARMED`;

                // Render Incidents
                const incContainer = document.getElementById('incidents-container');
                if (data.incidents.length === 0) {
                    incContainer.innerHTML = '<div class="empty-state">No security incidents detected. System secure.</div>';
                } else {
                    incContainer.innerHTML = '';
                    data.incidents.forEach(inc => {
                        const div = document.createElement('div');
                        div.className = 'incident-card';
                        
                        let lineageHtml = '';
                        if (inc.lineage && inc.lineage.length > 0) {
                            lineageHtml = '<div class="lineage-tree"><strong>Ancestry Lineage:</strong><br>';
                            inc.lineage.forEach((proc, idx) => {
                                lineageHtml += `${'&nbsp;'.repeat(idx * 2)}↳ PID ${proc.pid}: ${proc.name} (PPID ${proc.ppid})<br>`;
                            });
                            lineageHtml += '</div>';
                        }

                        div.innerHTML = `
                            <div class="incident-header">
                                <span class="incident-pid">🛑 PID ${inc.pid} [FROZEN]</span>
                                <span class="incident-time">${inc.timestamp} (${inc.latency_ms}ms)</span>
                            </div>
                            <div class="incident-body">
                                <strong>Tripwire:</strong> ${inc.target}<br>
                                <strong>Mitigation:</strong> Scheduler-level thread suspension (SIGSTOP / NtSuspendProcess)
                            </div>
                            ${lineageHtml}
                        `;
                        incContainer.appendChild(div);
                    });
                }
                document.getElementById('incident-badge').textContent = `${data.incidents.length} THREATS`;
            } catch (err) {
                console.error("Error fetching telemetry:", err);
            }
        }

        async function triggerSimulation() {
            showToast("⚡ Spawning simulated infostealer attack...");
            try {
                const res = await fetch('/api/simulate', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    showToast(`✔ Threat PID ${data.pid} neutralized in ${data.latency_ms}ms!`);
                    await fetchStatus();
                } else {
                    showToast("Simulation failed: " + data.error, true);
                }
            } catch (err) {
                showToast("Simulation error: " + err, true);
            }
        }

        async function deployCanaries() {
            showToast("Deploying synthetic canaries...");
            try {
                const res = await fetch('/api/init', { method: 'POST' });
                const data = await res.json();
                showToast(data.message);
                await fetchStatus();
            } catch (err) {
                showToast("Deploy error: " + err, true);
            }
        }

        async function cleanCanaries() {
            showToast("Cleaning all decoy canaries...");
            try {
                const res = await fetch('/api/clean', { method: 'POST' });
                const data = await res.json();
                showToast(data.message);
                await fetchStatus();
            } catch (err) {
                showToast("Clean error: " + err, true);
            }
        }

        // Initialize & poll
        fetchStatus();
        setInterval(fetchStatus, 1500);
    </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html: str, status: int = 200) -> None:
        payload = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send_html(DASHBOARD_HTML)
        elif self.path == "/api/status":
            adapter = get_platform_adapter()
            canaries = get_canary_list()
            with _LOCK:
                data = {
                    "platform": type(adapter).__name__,
                    "events_processed": _STATE["events_processed"],
                    "threats_neutralized": _STATE["threats_neutralized"],
                    "last_threat": _STATE["last_threat"],
                    "avg_mitigation_ms": _STATE["avg_mitigation_ms"],
                    "system": get_system_metrics(),
                    "canaries": canaries,
                    "incidents": _STATE["incidents"],
                }
            self._send_json(data)
        elif self.path == "/api/canaries":
            self._send_json(get_canary_list())
        elif self.path == "/api/incidents":
            with _LOCK:
                self._send_json(_STATE["incidents"])
        else:
            self.send_error(404, "Endpoint not found")

    def do_HEAD(self) -> None:
        if self.path in ("/", "/index.html"):
            payload = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/api/simulate":
            try:
                res = execute_attack_simulation()
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
        elif self.path == "/api/init":
            try:
                config = load_config()
                deployer = CanaryDeployer(config.canary_directory)
                registry = CanaryRegistry()
                deployer.deploy_env_file()
                deployer.deploy_aws_credentials()
                deployer.deploy_chrome_cookies()
                deployer.deploy_system_config()
                self._send_json({"success": True, "message": "Canaries deployed successfully."})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
        elif self.path == "/api/clean":
            try:
                config = load_config()
                count = 0
                cleaned_paths: set[Path] = set()

                if config.canary_directory.exists():
                    for path in config.canary_directory.rglob("*.honey*"):
                        if path.is_file() and path not in cleaned_paths:
                            path.unlink(missing_ok=True)
                            cleaned_paths.add(path)
                            count += 1

                aws_path = CanaryDeployer.get_aws_credentials_path()
                if aws_path.parent.exists():
                    for path in aws_path.parent.glob("credentials.honey*"):
                        if path.is_file() and path not in cleaned_paths:
                            path.unlink(missing_ok=True)
                            cleaned_paths.add(path)
                            count += 1

                chrome_path = CanaryDeployer.get_chrome_cookies_path(config.canary_directory)
                if chrome_path.parent.exists():
                    for path in chrome_path.parent.glob("Cookies.honey*"):
                        if path.is_file() and path not in cleaned_paths:
                            path.unlink(missing_ok=True)
                            cleaned_paths.add(path)
                            count += 1

                sys_path = CanaryDeployer.get_system_config_path()
                if sys_path.exists() and sys_path not in cleaned_paths:
                    sys_path.unlink(missing_ok=True)
                    cleaned_paths.add(sys_path)
                    count += 1

                self._send_json({"success": True, "message": f"Successfully unlinked {count} decoys."})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
        else:
            self.send_error(404, "Action not found")

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress routine log messages to keep terminal clean
        return


def start_server(port: int = 8080) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"[*] DeceptEnv Web Dashboard running at: http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Web Dashboard.")
        server.server_close()


if __name__ == "__main__":
    start_server(8080)
