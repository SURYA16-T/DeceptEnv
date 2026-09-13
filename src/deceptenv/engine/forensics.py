import logging
import os
import re

import psutil
from pydantic import BaseModel, Field

from deceptenv.config import SecurityConfig
from deceptenv.platform import get_platform_adapter

logger = logging.getLogger(__name__)

class ProcessInfo(BaseModel):
    pid: int
    ppid: int
    name: str
    cmdline: list[str]

class NetworkConnection(BaseModel):
    ip: str
    port: int
    state: str

class ForensicReport(BaseModel):
    lineage: list[ProcessInfo] = Field(default_factory=list)
    network_sockets: list[NetworkConnection] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_ips: list[str] = Field(default_factory=list)
    extracted_base64: list[str] = Field(default_factory=list)

class ForensicsExtractor:
    """Bounded, safe extraction of process information to prevent DoS."""
    
    URL_REGEX = re.compile(rb"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
    IP_REGEX = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    B64_REGEX = re.compile(rb"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.platform = get_platform_adapter()
        
    def dump_memory(self, pid: int) -> bytes:
        """
        Extract memory safely. 
        Will abort if the size exceeds `config.max_forensic_dump_size_bytes`.
        """
        logger.info(f"Initiating bounded memory dump for PID {pid}")
        max_bytes = self.config.max_forensic_dump_size_bytes
        
        # Read /proc/{pid}/mem based on readable maps for Linux. 
        # Safely fallback to empty bytes on error or non-Linux OS.
        mem_data = b""
        if os.name != "posix":
            return mem_data
            
        try:
            maps_path = f"/proc/{pid}/maps"
            mem_path = f"/proc/{pid}/mem"
            
            if not os.path.exists(maps_path) or not os.path.exists(mem_path):
                return mem_data
                
            regions = []
            with open(maps_path, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].startswith("r"):
                        addr_range = parts[0].split("-")
                        start = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                        regions.append((start, end))
            
            with open(mem_path, "rb") as mem_file:
                for start, end in regions:
                    if len(mem_data) >= max_bytes:
                        break
                    
                    size_to_read = min(end - start, max_bytes - len(mem_data))
                    mem_file.seek(start)
                    chunk = mem_file.read(size_to_read)
                    mem_data += chunk
                    
        except (PermissionError, IOError, OSError, ProcessLookupError) as e:
            logger.debug(f"Failed to read memory for PID {pid}: {e}")
            
        return mem_data
        
    def extract_lineage(self, pid: int) -> list[ProcessInfo]:
        """Get process tree lineage to find the root infostealer."""
        lineage_pids = self.platform.get_process_lineage(pid)
        infos = []
        for p in [pid] + lineage_pids:
            try:
                proc = psutil.Process(p)
                infos.append(
                    ProcessInfo(
                        pid=proc.pid,
                        ppid=proc.ppid(),
                        name=proc.name(),
                        cmdline=proc.cmdline()
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return infos

    def capture_snapshot(self, pid: int) -> ForensicReport:
        report = ForensicReport()
        report.lineage = self.extract_lineage(pid)
        
        try:
            proc = psutil.Process(pid)
            conns = proc.connections(kind="inet")
            for c in conns:
                if c.raddr:
                    report.network_sockets.append(
                        NetworkConnection(
                            ip=c.raddr.ip,
                            port=c.raddr.port,
                            state=c.status
                        )
                    )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        mem = self.dump_memory(pid)
        if mem:
            urls = set(self.URL_REGEX.findall(mem))
            ips = set(self.IP_REGEX.findall(mem))
            b64s = set(self.B64_REGEX.findall(mem))
            
            report.extracted_urls = [u.decode('utf-8', errors='ignore') for u in urls]
            report.extracted_ips = [i.decode('utf-8', errors='ignore') for i in ips]
            report.extracted_base64 = [b.decode('utf-8', errors='ignore') for b in b64s]
            
        return report
