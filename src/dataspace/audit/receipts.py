"""Messages exchanged with the transparency log."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from dataspace.identity.proofs import Signed


class Receipt(Signed):
    """A participant's signed commitment to one of its audit events."""

    actor: str
    event_type: str
    subject: str | None = None
    digest: str
    """Hash of the committed audit event (SHA-256, hex)."""
    timestamp: datetime


class SignedTreeHead(Signed):
    log: str
    tree_size: int
    root_hash: str
    timestamp: datetime


class InclusionProof(BaseModel):
    index: int
    tree_size: int
    leaf_hash: str
    path: list[str]


class ConsistencyProof(BaseModel):
    first: int
    second: int
    path: list[str]


class AppendResult(BaseModel):
    index: int
    leaf_hash: str
    tree_head: SignedTreeHead
