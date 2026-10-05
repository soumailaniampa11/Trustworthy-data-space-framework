"""Dataset offers published in the catalog.

The catalog only stores the offer (metadata, owner, checksum, policy); the
bytes stay in the provider's connector, which preserves data sovereignty.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from dataspace.catalog.metadata import DatasetMetadata


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Dataset(BaseModel):
    id: str
    owner_id: str
    metadata: DatasetMetadata
    checksum: str
    """SHA-256 of the content, used by consumers to verify integrity."""
    size: int
    policy_id: str | None = None
    published_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    withdrawn: bool = False
