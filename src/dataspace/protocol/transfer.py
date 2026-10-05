"""Transfer process (pull model).

The consumer asks for a transfer under an agreement, presenting fresh
credentials. The provider re-evaluates the *current* policy (continuous
usage control) and, if still permitted, returns a single-use, short-lived
data address. The consumer pulls the data from the provider's data plane and
verifies its checksum and the provider's signature.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel

from dataspace.identity.credentials import VerifiablePresentation
from dataspace.identity.proofs import Signed


class TransferState(str, Enum):
    REQUESTED = "REQUESTED"
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    TERMINATED = "TERMINATED"


class TransferRequest(BaseModel):
    transfer_id: str
    agreement_id: str
    consumer: str
    presentation: VerifiablePresentation


class DataAddress(BaseModel):
    endpoint: str
    token: str
    expires: datetime


class TransferResponse(BaseModel):
    transfer_id: str
    state: TransferState
    reason: str | None = None
    data_address: DataAddress | None = None


class Transfer(BaseModel):
    id: str
    role: str
    agreement_id: str
    dataset_id: str
    counterparty: str
    state: TransferState
    reason: str | None = None
    checksum: str | None = None
    size: int | None = None
    created: datetime
    completed: datetime | None = None


class DataAttestation(Signed):
    """Provider's signed statement of what it delivered in a transfer."""

    transfer_id: str
    dataset_id: str
    checksum: str
