"""A consultant's review decision about a finding, as plain data (ADR 0007)."""

from dataclasses import dataclass
from datetime import datetime

from app.domain.enums import Severity


@dataclass(frozen=True)
class Review:
    status: str  # open / confirmed / false_positive / accepted_risk
    severity_override: Severity | None
    justification: str | None
    reviewed_by: str
    reviewed_at: datetime
