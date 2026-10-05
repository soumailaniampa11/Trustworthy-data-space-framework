"""Contract negotiation (after the Dataspace Protocol state machine, simplified).

    consumer                                   provider
       │  ContractRequest (+ presentation)  ──►  │  verify identity & claims, evaluate policy
       │  ◄── AGREED + agreement (provider sig)  │  or TERMINATED + reason
       │  verify, countersign                    │
       │  AgreementVerification ───────────────► │  verify consumer signature
       │  ◄──────────────────────── FINALIZED    │

The resulting agreement carries both signatures: neither party can later
deny its terms (non-repudiation).
"""

from __future__ import annotations

import secrets
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from dataspace.identity.credentials import VerifiablePresentation
from dataspace.identity.proofs import Proof, Signed
from dataspace.policy.model import Action, Duty


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


class NegotiationState(str, Enum):
    REQUESTED = "REQUESTED"
    AGREED = "AGREED"
    FINALIZED = "FINALIZED"
    TERMINATED = "TERMINATED"


class ContractRequest(BaseModel):
    negotiation_id: str
    consumer: str
    dataset_id: str
    policy_uid: str
    action: Action
    purpose: str | None = None
    presentation: VerifiablePresentation


class ContractAgreement(Signed):
    id: str
    negotiation_id: str
    provider: str
    consumer: str
    dataset_id: str
    checksum: str
    action: Action
    purpose: str | None = None
    policy_uid: str
    policy_version: int
    rule_id: str | None = None
    obligations: list[Duty] = Field(default_factory=list)
    valid_until: datetime | None = None
    issued: datetime
    consumer_proof: Proof | None = None

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"proof", "consumer_proof"}, exclude_none=True)


class AgreementVerification(BaseModel):
    consumer_proof: Proof


class NegotiationResponse(BaseModel):
    negotiation_id: str
    state: NegotiationState
    reason: str | None = None
    agreement: ContractAgreement | None = None


class Negotiation(BaseModel):
    """A negotiation as recorded by either party."""

    id: str
    role: str
    counterparty: str
    dataset_id: str
    action: Action
    purpose: str | None = None
    state: NegotiationState
    reason: str | None = None
    agreement: ContractAgreement | None = None
    created: datetime
    updated: datetime


class AgreementRecord(BaseModel):
    """Provider-side enforcement state of an agreement."""

    agreement: ContractAgreement
    uses: int = 0
    revoked: bool = False
    revocation_reason: str | None = None
