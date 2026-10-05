"""Tamper-evident audit log.

Each event stores the hash of the previous event, forming a hash chain:
modifying, deleting or reordering any past event breaks ``verify()``.
Events can optionally be appended to a JSON Lines file.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from dataspace.core.exceptions import IntegrityError

GENESIS_HASH = "0" * 64


class Outcome(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class AuditEvent(BaseModel):
    sequence: int
    timestamp: datetime
    actor: str
    event_type: str
    resource: str | None = None
    outcome: Outcome = Outcome.SUCCESS
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"hash"})
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class AuditLogger:
    def __init__(self, path: str | Path | None = None):
        self._events: list[AuditEvent] = []
        self._path = Path(path) if path else None

    def log(
        self,
        actor: str,
        event_type: str,
        resource: str | None = None,
        outcome: Outcome = Outcome.SUCCESS,
        **details: Any,
    ) -> AuditEvent:
        event = AuditEvent(
            sequence=len(self._events),
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            event_type=event_type,
            resource=resource,
            outcome=outcome,
            details=details,
            previous_hash=self._events[-1].hash if self._events else GENESIS_HASH,
        )
        event.hash = event.compute_hash()
        self._events.append(event)
        if self._path:
            with self._path.open("a") as f:
                f.write(event.model_dump_json() + "\n")
        return event

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def query(
        self,
        actor: str | None = None,
        event_type: str | None = None,
        resource: str | None = None,
        outcome: Outcome | None = None,
    ) -> list[AuditEvent]:
        return [
            e
            for e in self._events
            if (actor is None or e.actor == actor)
            and (event_type is None or e.event_type == event_type)
            and (resource is None or e.resource == resource)
            and (outcome is None or e.outcome == outcome)
        ]

    def verify(self) -> bool:
        """Raise :class:`IntegrityError` if the chain was tampered with."""
        verify_chain(self._events)
        return True

    @classmethod
    def load(cls, path: str | Path) -> AuditLogger:
        logger = cls(path)
        lines = Path(path).read_text().splitlines() if Path(path).exists() else []
        logger._events = [AuditEvent.model_validate_json(line) for line in lines if line]
        logger.verify()
        return logger


def verify_chain(events: list[AuditEvent]) -> None:
    previous = GENESIS_HASH
    for index, event in enumerate(events):
        if event.sequence != index:
            raise IntegrityError(f"sequence gap at position {index}")
        if event.previous_hash != previous:
            raise IntegrityError(f"broken chain at event {index}")
        if event.compute_hash() != event.hash:
            raise IntegrityError(f"event {index} was modified")
        previous = event.hash
