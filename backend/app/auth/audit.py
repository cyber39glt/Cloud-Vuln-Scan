"""Writing to the append-only audit log (the database refuses changes and deletes).

Entries never contain secrets: no passwords, codes, tokens or keys. Details are run
through the log redactor as a second line of defence.
"""

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import redact_value
from app.storage.models import AuditEvent


@dataclass(frozen=True)
class Actor:
    type: str  # "user", "cli", "system", "anonymous"
    user_id: uuid.UUID | None = None
    email: str | None = None


SYSTEM = Actor("system")  # the background worker
CLI = Actor("cli")  # server-side command line (direct database access)
ANONYMOUS = Actor("anonymous")  # not logged in


def record(
    db: Session,
    action: str,
    actor: Actor,
    *,
    outcome: str = "success",
    client_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: object | None = None,
    ip_address: str | None = None,
    **details: Any,
) -> None:
    db.add(
        AuditEvent(
            action=action,
            outcome=outcome,
            actor_type=actor.type,
            actor_user_id=actor.user_id,
            actor_email=actor.email,
            client_id=client_id,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            ip_address=ip_address,
            details=redact_value(details),
        )
    )
