import asyncio
import logging
import os
from typing import Optional

from deceptenv.engine.forensics import ForensicReport, ForensicsExtractor
from deceptenv.exceptions import MitigatorRaceConditionError, OSPrimitiveError
from deceptenv.platform import get_platform_adapter

logger = logging.getLogger(__name__)

class ThreatMitigator:
    """Race-condition-safe process freezing logic."""
    
    def __init__(self, forensics: ForensicsExtractor) -> None:
        self.platform = get_platform_adapter()
        self.forensics = forensics
        self._action_lock = asyncio.Lock()
        
    async def freeze_threat(self, pid: int) -> Optional[ForensicReport]:
        """Safely suspend a process ensuring atomic checks where possible."""
        if pid <= 0:
            logger.error("Invalid PID received by mitigator.")
            return None
            
        # Self-harm prevention checks
        if pid == os.getpid():
            logger.error("Attempted to mitigate DeceptEnv itself. Aborting.")
            return None
            
        if pid == os.getppid():
            logger.error("Attempted to mitigate parent shell. Aborting.")
            return None

        # Check UID ownership
        current_owner = self.platform._get_current_user_sid() if os.name == 'nt' else os.getuid()
        try:
            threat_owner = self.platform.get_process_owner(pid)
            if threat_owner != current_owner:
                logger.error(f"Threat PID {pid} is not owned by current user. Aborting.")
                return None
        except ProcessLookupError:
            logger.warning(f"Process {pid} exited before ownership check.")
            return None

        # Acquire lock to prevent concurrent mitigations stepping on each other
        async with self._action_lock:
            try:
                # We attempt to suspend immediately to stop the threat
                success = self.platform.freeze_pid(pid)
                if not success:
                    raise MitigatorRaceConditionError(
                        f"Process {pid} exited before suspension could be applied."
                    )
                    
                logger.warning(f"Successfully suspended threat process: PID {pid}")
                
                # Initiate forensic snapshot
                report = self.forensics.capture_snapshot(pid)
                return report
                
            except OSPrimitiveError as e:
                logger.error(f"Failed to mitigate threat safely: {e}")
                raise
            except MitigatorRaceConditionError as e:
                logger.error(f"Mitigator Race Condition: {e}. Trigger secondary cleanup.")
                return None
