from __future__ import annotations

import base64

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.deps import current_participant, get_space
from dataspace import DataSpace
from dataspace.catalog import Dataset, DatasetMetadata, Sensitivity
from dataspace.identity.participant import Participant
from dataspace.policy import Rule

router = APIRouter(prefix="/datasets", tags=["datasets"])


class PublishDataset(BaseModel):
    id: str
    metadata: DatasetMetadata
    content_base64: str
    rules: list[Rule] | None = None


@router.post("", response_model=Dataset, status_code=201)
def publish(
    body: PublishDataset,
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    data = base64.b64decode(body.content_base64)
    return space.publish_dataset(participant.id, body.id, data, body.metadata, body.rules)


@router.get("", response_model=list[Dataset])
def search(
    q: str | None = None,
    owner: str | None = None,
    sensitivity: Sensitivity | None = None,
    space: DataSpace = Depends(get_space),
):
    return space.catalog.search(q, owner, sensitivity)


@router.get("/{dataset_id}", response_model=Dataset)
def get_dataset(dataset_id: str, space: DataSpace = Depends(get_space)):
    return space.catalog.get(dataset_id)


@router.delete("/{dataset_id}", response_model=Dataset)
def withdraw(
    dataset_id: str,
    participant: Participant = Depends(current_participant),
    space: DataSpace = Depends(get_space),
):
    return space.withdraw_dataset(participant.id, dataset_id)
