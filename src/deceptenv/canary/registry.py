import hashlib
import threading
from pathlib import Path
from typing import Any, Dict

from deceptenv.exceptions import CanaryRegistryCorruption


class CanaryRegistry:
    """Thread-safe state manager for tracked canaries."""
    
    def __init__(self) -> None:
        self._canaries: Dict[Path, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        
    def _compute_hash(self, path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    def register(self, path: Path) -> None:
        """Register a path securely and compute its baseline hash."""
        with self._lock:
            resolved_path = path.resolve()
            if resolved_path in self._canaries:
                raise CanaryRegistryCorruption(
                    f"Canary {resolved_path} already registered."
                )
            
            file_hash = self._compute_hash(resolved_path)
            self._canaries[resolved_path] = {"hash": file_hash}
            
    def is_canary(self, path: Path) -> bool:
        """Check if a given path is a registered canary."""
        with self._lock:
            return path.resolve() in self._canaries
            
    def get_canary_metadata(self, path: Path) -> dict[str, Any]:
        """Retrieve metadata for a canary."""
        with self._lock:
            resolved = path.resolve()
            if resolved not in self._canaries:
                raise CanaryRegistryCorruption(
                    f"Canary {resolved} is not tracked."
                )
            # Return a copy to avoid external mutation
            return self._canaries[resolved].copy()
            
    def unregister(self, path: Path) -> None:
        """Remove a canary from tracking."""
        with self._lock:
            resolved = path.resolve()
            if resolved in self._canaries:
                del self._canaries[resolved]

    def get_all_paths(self) -> list[Path]:
        """Return a list of all currently tracked canary paths."""
        with self._lock:
            return list(self._canaries.keys())
