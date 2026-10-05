"""Transfer processes between connectors (control plane side)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from dataspace.access.authorization import AuthorizationService
from dataspace.audit.logger import AuditLogger, Outcome
from dataspace.catalog.catalog import Catalog
from dataspace.core.exceptions import DataSpaceError, NotFoundError, TransferError
from dataspace.exchange.connector import Connector
from dataspace.identity.participant import Participant, ParticipantRegistry


class TransferState(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"


class TransferProcess(BaseModel):
    id: str = Field(default_factory=lambda: f"tx-{uuid.uuid4().hex[:10]}")
    grant_id: str
    dataset_id: str
    provider_id: str
    consumer_id: str
    state: TransferState = TransferState.STARTED
    checksum: str | None = None
    size: int | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    error: str | None = None


class TransferService:
    def __init__(
        self,
        registry: ParticipantRegistry,
        catalog: Catalog,
        authz: AuthorizationService,
        audit: AuditLogger,
        connectors: dict[str, Connector],
    ):
        self.registry = registry
        self.catalog = catalog
        self.authz = authz
        self.audit = audit
        self.connectors = connectors
        self._processes: dict[str, TransferProcess] = {}

    def get(self, transfer_id: str) -> TransferProcess:
        try:
            return self._processes[transfer_id]
        except KeyError:
            raise NotFoundError(f"transfer '{transfer_id}' not found") from None

    def transfer(self, grant_id: str, consumer: Participant) -> TransferProcess:
        # Enforcement happens before any byte leaves the provider.
        grant = self.authz.use_grant(grant_id, consumer)
        process = TransferProcess(
            grant_id=grant.id,
            dataset_id=grant.dataset_id,
            provider_id=grant.provider_id,
            consumer_id=consumer.id,
        )
        self._processes[process.id] = process
        try:
            dataset = self.catalog.get(grant.dataset_id)
            provider = self.registry.get(grant.provider_id)
            provider_conn = self._connector(grant.provider_id)
            consumer_conn = self._connector(consumer.id)
            data, signature = provider_conn.provide(dataset.id)
            consumer_conn.receive(
                process.id, data, dataset.checksum, signature, provider.connector_key or ""
            )
        except DataSpaceError as exc:
            process.state = TransferState.FAILED
            process.error = str(exc)
            self.audit.log(consumer.id, "transfer.completed", grant.dataset_id, Outcome.FAILURE,
                           transfer_id=process.id, error=str(exc))
            raise TransferError(str(exc)) from exc

        process.state = TransferState.COMPLETED
        process.checksum = dataset.checksum
        process.size = len(data)
        process.completed_at = datetime.now(timezone.utc)
        self.audit.log(consumer.id, "transfer.completed", dataset.id, Outcome.SUCCESS,
                       transfer_id=process.id, grant_id=grant.id, provider=provider.id,
                       checksum=dataset.checksum, size=len(data))
        return process

    def _connector(self, participant_id: str) -> Connector:
        try:
            return self.connectors[participant_id]
        except KeyError:
            raise TransferError(f"participant '{participant_id}' has no connector") from None
