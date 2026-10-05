from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.deps import current_participant, get_space
from dataspace import DataSpace
from dataspace.core.exceptions import NotFoundError
from dataspace.identity.participant import Participant
from dataspace.policy import Policy, Rule

router = APIRouter(tags=["policies"])


class SetPolicy(BaseModel):
    rules: list[Rule]


@router.put("/datasets/{dataset_id}/policy", response_model=Policy)
def set_policy(
    dataset_id: str,
    body: SetPolicy,
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    return space.set_policy(participant.id, dataset_id, body.rules)


@router.get("/datasets/{dataset_id}/policy", response_model=Policy)
def get_dataset_policy(dataset_id: str, space: DataSpace = Depends(get_space)):
    dataset = space.catalog.get(dataset_id)
    if not dataset.policy_id:
        raise NotFoundError(f"dataset '{dataset_id}' has no policy")
    return space.policies.get(dataset.policy_id)


@router.get("/policies/{policy_id}", response_model=Policy)
def get_policy(policy_id: str, space: DataSpace = Depends(get_space)):
    return space.policies.get(policy_id)
