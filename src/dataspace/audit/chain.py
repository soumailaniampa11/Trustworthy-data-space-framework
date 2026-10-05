"""Local, hash-chained audit trail of a service.

Each event commits to its predecessor's hash, so any modification, deletion
or reordering of past events is detected by ``verify``. Because the operator
of the trail could still recompute the whole chain, each event hash is also
anchored in the external transparency log (see ``Anchor``).
"""

from __future__ import annotations

import threading
from datetime import datetime
from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, Field

from dataspace.common.clock import utcnow
from dataspace.common.crypto import canonical_json, sha256_hex
from dataspace.common.errors import IntegrityViolation
from dataspace.common.store import DocumentStore

GENESIS = "0" * 64


class Outcome(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class Anchor(BaseModel):
    """Position of the event's receipt in the transparency log."""

    index: int
    leaf_hash: str


class AuditEvent(BaseModel):
    sequence: int
    timestamp: datetime
    actor: str
    event_type: str
    subject: str | None = None
    outcome: Outcome = Outcome.SUCCESS
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    hash: str = ""
    anchor: Anchor | None = None

    def compute_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"hash", "anchor"})
        return sha256_hex(canonical_json(body))


class AuditTrail:
    COLLECTION = "audit"

    def __init__(self, store: DocumentStore, anchor: Callable[[AuditEvent], Anchor | None] | None = None):
        self.store = store
        self.anchor = anchor
        self._lock = threading.Lock()

    def record(self, actor: str, event_type: str, subject: str | None = None,
               outcome: Outcome = Outcome.SUCCESS, **details: Any) -> AuditEvent:
        with self._lock:
            events = self.events()
            event = AuditEvent(
                sequence=len(events),
                timestamp=utcnow(),
                actor=actor,
                event_type=event_type,
                subject=subject,
                outcome=outcome,
                details=details,
                previous_hash=events[-1].hash if events else GENESIS,
            )
            event.hash = event.compute_hash()
            self.store.put(self.COLLECTION, str(event.sequence), event)
        if self.anchor:
            event.anchor = self.anchor(event)
            self.store.put(self.COLLECTION, str(event.sequence), event)
        return event

    def events(self) -> list[AuditEvent]:
        return self.store.find(self.COLLECTION, AuditEvent)

    def verify(self) -> int:
        """Return the number of events, or raise ``IntegrityViolation``."""
        events = self.events()
        verify_chain(events)
        return len(events)


def verify_chain(events: list[AuditEvent]) -> None:
    previous = GENESIS
    for position, event in enumerate(events):
        if event.sequence != position:
            raise IntegrityViolation(f"sequence gap at position {position}")
        if event.previous_hash != previous:
            raise IntegrityViolation(f"broken chain at event {position}")
        if event.compute_hash() != event.hash:
            raise IntegrityViolation(f"event {position} was modified")
        previous = event.hash
