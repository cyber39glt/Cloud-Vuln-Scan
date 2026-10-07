"""Definitions shared by every cloud connector."""

from dataclasses import dataclass, field


class ReadOnlyViolation(PermissionError):
    """Raised when code attempts a cloud API call that is not on the read-only
    allowlist. It always indicates a bug: it must stop the operation, never be
    treated as an ordinary error or a collection gap."""


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # "ok", "failed" or "skipped"
    detail: str = ""


@dataclass
class ValidationReport:
    """Result of a pre-scan connection check (AWS account or Azure subscription)."""

    account_id: str
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.status != "failed" for c in self.checks)

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(name, status, detail))
