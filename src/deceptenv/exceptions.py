class DeceptEnvError(Exception):
    """Base exception class for all DeceptEnv errors."""
    pass

class ProcessOwnershipViolation(DeceptEnvError):
    """
    Raised when an attempt to act on a process not owned or accessible by us occurs.
    """
    pass

class SuspensionFailedError(DeceptEnvError):
    """Raised when the mitigation engine fails to suspend a threat."""
    pass

class PlatformNotSupportedError(DeceptEnvError):
    """Raised when DeceptEnv is executed on an unsupported OS/architecture."""
    pass

class ConfigurationError(DeceptEnvError):
    """Raised when the configuration is invalid or maliciously tampered with."""
    pass

class OSPrimitiveError(DeceptEnvError):
    """Raised when an OS-level operation fails (e.g., failed to suspend process)."""
    pass

class SecurityBoundaryViolation(DeceptEnvError):
    """
    Raised when an operation attempts to cross a secure boundary 
    (e.g., path traversal, memory limit exceeded).
    """
    pass

class MitigatorRaceConditionError(DeceptEnvError):
    """
    Raised if the mitigator detects the target process state changed mid-operation,
    preventing safe suspension.
    """
    pass

class CanaryRegistryCorruption(DeceptEnvError):
    """Raised if the thread-safe canary registry detects anomalous internal state."""
    pass
