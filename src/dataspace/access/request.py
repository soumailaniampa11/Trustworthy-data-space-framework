"""Access requests and the grants (usage agreements) that result from them."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from dataspace.policy.policy import Action, Duty


class RequestStatus(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"


class AccessRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"req-{uuid.uuid4().hex[:10]}")
    requester_id: str
    dataset_id: str
    action: Action
    purpose: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: RequestStatus | None = None
    reason: str | None = None
    grant_id: str | None = None


class GrantStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"


class AccessGrant(BaseModel):
    """A usage agreement between a provider and a consumer for one dataset."""

    id: str = Field(default_factory=lambda: f"grant-{uuid.uuid4().hex[:10]}")
    request_id: str
    dataset_id: str
    provider_id: str
    consumer_id: str
    action: Action
    purpose: str | None = None
    policy_id: str
    policy_version: int
    obligations: list[Duty] = Field(default_factory=list)
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    max_uses: int | None = None
    uses: int = 0
    status: GrantStatus = GrantStatus.ACTIVE

    def refresh_status(self, now: datetime | None = None) -> GrantStatus:
        now = now or datetime.now(timezone.utc)
        if self.status == GrantStatus.ACTIVE:
            if self.expires_at and now >= self.expires_at:
                self.status = GrantStatus.EXPIRED
            elif self.max_uses is not None and self.uses >= self.max_uses:
                self.status = GrantStatus.EXHAUSTED
        return self.status
