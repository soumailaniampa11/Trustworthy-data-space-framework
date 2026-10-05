"""Participants, their cryptographic keys, and the participant registry."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from dataspace.core.exceptions import AlreadyExistsError, NotFoundError


class Role(str, Enum):
    PROVIDER = "provider"
    CONSUMER = "consumer"
    AUTHORITY = "authority"


class ParticipantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode())


class KeyPair:
    """Ed25519 key pair held by a participant (the private key never leaves it)."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._private = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> str:
        raw = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return _b64(raw)

    def sign(self, message: bytes) -> str:
        return _b64(self._private.sign(message))


def verify_signature(public_key: str, message: bytes, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public_key)).verify(_unb64(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


class Participant(BaseModel):
    """A member of the data space.

    ``attributes`` carry the claims that policies are evaluated against
    (e.g. ``country``, ``sector``, ``certification``).
    """

    id: str
    name: str
    organization: str
    public_key: str
    """Identity key, used for challenge-response authentication."""
    connector_key: str | None = None
    """Key of the participant's connector, used to sign provided data."""
    roles: set[Role] = Field(default_factory=lambda: {Role.CONSUMER})
    attributes: dict[str, Any] = Field(default_factory=dict)
    status: ParticipantStatus = ParticipantStatus.ACTIVE
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_active(self) -> bool:
        return self.status == ParticipantStatus.ACTIVE

    def has_role(self, role: Role) -> bool:
        return role in self.roles


class ParticipantRegistry:
    """Authoritative directory of participants and their public keys."""

    def __init__(self) -> None:
        self._participants: dict[str, Participant] = {}

    def register(self, participant: Participant) -> Participant:
        if participant.id in self._participants:
            raise AlreadyExistsError(f"participant '{participant.id}' already registered")
        self._participants[participant.id] = participant
        return participant

    def get(self, participant_id: str) -> Participant:
        try:
            return self._participants[participant_id]
        except KeyError:
            raise NotFoundError(f"participant '{participant_id}' not found") from None

    def list(self) -> list[Participant]:
        return list(self._participants.values())

    def set_status(self, participant_id: str, status: ParticipantStatus) -> Participant:
        participant = self.get(participant_id)
        participant.status = status
        return participant

    def __contains__(self, participant_id: str) -> bool:
        return participant_id in self._participants
