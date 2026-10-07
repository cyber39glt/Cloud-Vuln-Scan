"""Fixed vocabularies shared across the platform.

StrEnum values are plain strings ("aws", "high", ...), so they serialize cleanly to
JSON, CSV and the database without conversion code.
"""

from enum import StrEnum


class Provider(StrEnum):
    AWS = "aws"
    AZURE = "azure"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        """Higher number = more severe. Used for sorting."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


class Category(StrEnum):
    IDENTITY_ACCESS = "identity_access"
    NETWORK = "network"
    STORAGE = "storage"
    EXPOSURE = "exposure"
    LOGGING_MONITORING = "logging_monitoring"


class CheckStatus(StrEnum):
    # S105 suppressed: the linter mistakes "pass" for a hard-coded password.
    PASS = "pass"  # noqa: S105  Evaluated; no weakness found.
    FAIL = "fail"  # Evaluated; weakness found. Becomes a Finding.
    ERROR = "error"  # Could NOT be evaluated (missing data, crash). Never a pass.
    NOT_APPLICABLE = "not_applicable"  # Nothing in scope to evaluate.


class Framework(StrEnum):
    CIS_AWS = "cis_aws"
    CIS_AZURE = "cis_azure"
    NIST_CSF = "nist_csf"
    SOC2 = "soc2"


class ScanStage(StrEnum):
    """Progress of a scan, in the order a scan goes through them."""

    WAITING = "waiting"
    CONNECTING = "connecting"  # obtaining read-only access, confirming the account
    COLLECTING = "collecting"
    EVALUATING = "evaluating"
    SAVING = "saving"
    DONE = "done"
