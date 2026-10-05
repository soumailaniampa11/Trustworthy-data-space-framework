"""Challenge-response authentication and signed session tokens.

1. The participant asks for a challenge (random nonce).
2. It signs the nonce with its private key.
3. The identity provider checks the signature against the registered public
   key and issues a session token signed by the data space authority.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from dataspace.core.exceptions import AuthenticationError, NotFoundError
from dataspace.identity.participant import (
    KeyPair,
    Participant,
    ParticipantRegistry,
    _b64,
    _unb64,
    verify_signature,
)


@dataclass(frozen=True)
class TokenClaims:
    participant_id: str
    issued_at: datetime
    expires_at: datetime
    token_id: str


class IdentityProvider:
    def __init__(
        self,
        registry: ParticipantRegistry,
        token_ttl: timedelta = timedelta(hours=1),
        challenge_ttl: timedelta = timedelta(minutes=2),
        authority_keys: KeyPair | None = None,
    ):
        self.registry = registry
        self.token_ttl = token_ttl
        self.challenge_ttl = challenge_ttl
        self._keys = authority_keys or KeyPair()
        self._challenges: dict[str, tuple[str, datetime]] = {}
        self._revoked_tokens: set[str] = set()

    @property
    def public_key(self) -> str:
        return self._keys.public_key

    def create_challenge(self, participant_id: str) -> str:
        self.registry.get(participant_id)  # raises NotFoundError for unknown participants
        nonce = secrets.token_urlsafe(32)
        self._challenges[participant_id] = (nonce, datetime.now(timezone.utc) + self.challenge_ttl)
        return nonce

    def authenticate(self, participant_id: str, signature: str) -> str:
        """Verify the signed challenge and return a session token."""
        entry = self._challenges.pop(participant_id, None)  # single use
        if entry is None:
            raise AuthenticationError("no pending challenge")
        nonce, expires_at = entry
        if datetime.now(timezone.utc) > expires_at:
            raise AuthenticationError("challenge expired")
        participant = self._active_participant(participant_id)
        if not verify_signature(participant.public_key, nonce.encode(), signature):
            raise AuthenticationError("invalid challenge signature")
        return self._issue_token(participant_id)

    def verify_token(self, token: str) -> Participant:
        claims = self.decode_token(token)
        return self._active_participant(claims.participant_id)

    def decode_token(self, token: str) -> TokenClaims:
        try:
            payload_b64, signature = token.split(".")
            payload = _unb64(payload_b64)
            data = json.loads(payload)
        except ValueError:
            raise AuthenticationError("malformed token") from None
        if not verify_signature(self.public_key, payload, signature):
            raise AuthenticationError("invalid token signature")
        claims = TokenClaims(
            participant_id=data["sub"],
            issued_at=datetime.fromisoformat(data["iat"]),
            expires_at=datetime.fromisoformat(data["exp"]),
            token_id=data["jti"],
        )
        if datetime.now(timezone.utc) > claims.expires_at:
            raise AuthenticationError("token expired")
        if claims.token_id in self._revoked_tokens:
            raise AuthenticationError("token revoked")
        return claims

    def revoke_token(self, token: str) -> None:
        self._revoked_tokens.add(self.decode_token(token).token_id)

    def _issue_token(self, participant_id: str) -> str:
        now = datetime.now(timezone.utc)
        payload = json.dumps(
            {
                "sub": participant_id,
                "iat": now.isoformat(),
                "exp": (now + self.token_ttl).isoformat(),
                "jti": secrets.token_hex(8),
            },
            sort_keys=True,
        ).encode()
        return f"{_b64(payload)}.{self._keys.sign(payload)}"

    def _active_participant(self, participant_id: str) -> Participant:
        try:
            participant = self.registry.get(participant_id)
        except NotFoundError:
            raise AuthenticationError("unknown participant") from None
        if not participant.is_active:
            raise AuthenticationError(f"participant is {participant.status.value}")
        return participant
