from __future__ import annotations

import base64

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.deps import current_participant, get_space
from dataspace import DataSpace
from dataspace.access import AccessGrant, AccessRequest
from dataspace.audit import AuditEvent
from dataspace.exchange import TransferProcess
from dataspace.identity.participant import Participant
from dataspace.policy import Action

router = APIRouter(tags=["access"])


class RequestAccess(BaseModel):
    dataset_id: str
    action: Action
    purpose: str | None = None
    max_uses: int | None = None


class TransferResult(BaseModel):
    process: TransferProcess
    content_base64: str


@router.post("/access/requests", response_model=AccessRequest, status_code=201)
def request_access(
    body: RequestAccess,
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    return space.authz.request_access(
        participant, body.dataset_id, body.action, body.purpose, body.max_uses
    )


@router.get("/access/grants", response_model=list[AccessGrant])
def my_grants(
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    return space.authz.grants_for(participant.id)


@router.post("/access/grants/{grant_id}/revoke", response_model=AccessGrant)
def revoke(
    grant_id: str,
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    return space.authz.revoke_grant(grant_id, participant.id)


@router.post("/access/grants/{grant_id}/transfer", response_model=TransferResult)
def transfer(
    grant_id: str,
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    process, data = space.transfer(grant_id, participant.id)
    return TransferResult(process=process, content_base64=base64.b64encode(data).decode())


@router.get("/audit", response_model=list[AuditEvent])
def audit_trail(
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    """Events performed by the caller or concerning datasets it owns."""
    owned = {d.id for d in space.catalog.search(owner_id=participant.id)}
    return [e for e in space.audit.events if e.actor == participant.id or e.resource in owned]


@router.get("/audit/verify")
def verify_audit(space: DataSpace = Depends(get_space)):
    return {"valid": space.audit.verify(), "events": len(space.audit.events)}
