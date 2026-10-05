from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.deps import current_participant, get_space
from dataspace import DataSpace
from dataspace.identity.participant import Participant, Role

router = APIRouter(tags=["participants"])


class RegisterParticipant(BaseModel):
    id: str
    name: str
    organization: str
    public_key: str
    roles: list[Role] = Field(default_factory=lambda: [Role.CONSUMER])
    attributes: dict[str, Any] = Field(default_factory=dict)


class ChallengeRequest(BaseModel):
    participant_id: str


class TokenRequest(BaseModel):
    participant_id: str
    signature: str


@router.post("/participants", response_model=Participant, status_code=201)
def register(body: RegisterParticipant, space: DataSpace = Depends(get_space)):
    return space.register(
        body.id, body.name, body.organization, body.public_key, body.roles, body.attributes
    )


@router.get("/participants", response_model=list[Participant])
def list_participants(space: DataSpace = Depends(get_space)):
    return space.registry.list()


@router.get("/participants/me", response_model=Participant)
def me(participant: Participant = Depends(current_participant)):
    return participant


@router.get("/participants/{participant_id}", response_model=Participant)
def get_participant(participant_id: str, space: DataSpace = Depends(get_space)):
    return space.registry.get(participant_id)


@router.post("/auth/challenge")
def challenge(body: ChallengeRequest, space: DataSpace = Depends(get_space)):
    return {"challenge": space.identity.create_challenge(body.participant_id)}


@router.post("/auth/token")
def token(body: TokenRequest, space: DataSpace = Depends(get_space)):
    return {
        "access_token": space.identity.authenticate(body.participant_id, body.signature),
        "token_type": "bearer",
    }
