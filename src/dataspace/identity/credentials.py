"""W3C Verifiable Credentials and Presentations.

Participants do not *declare* their attributes: a trusted issuer attests
them in credentials, and policies are evaluated only against claims that
come from valid, unexpired, unrevoked credentials of trusted issuers,
presented by their subject in a fresh, audience-bound presentation.
"""

from __future__ import annotations

import secrets
import threading
from datetime import datetime, timedelta
from typing import Any

import httpx
from pydantic import BaseModel, Field

from dataspace.common.clock import utcnow
from dataspace.common.errors import DataSpaceError, Unauthenticated
from dataspace.common.http import call
from dataspace.identity.did import DIDResolver
from dataspace.identity.proofs import Signed

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"


class CredentialStatus(BaseModel):
    id: str
    """URL of the issuer's signed revocation list."""
    type: str = "RevocationList"


class VerifiableCredential(Signed):
    context: list[str] = Field(default_factory=lambda: [VC_CONTEXT], alias="@context")
    id: str = Field(default_factory=lambda: f"urn:uuid:{secrets.token_hex(16)}")
    type: list[str]
    issuer: str
    validFrom: datetime
    validUntil: datetime | None = None
    credentialSubject: dict[str, Any]
    credentialStatus: CredentialStatus | None = None

    @property
    def subject(self) -> str:
        return self.credentialSubject["id"]


class RevocationList(Signed):
    id: str
    issuer: str
    updated: datetime
    revoked: list[str] = Field(default_factory=list)


class VerifiablePresentation(Signed):
    context: list[str] = Field(default_factory=lambda: [VC_CONTEXT], alias="@context")
    type: list[str] = Field(default_factory=lambda: ["VerifiablePresentation"])
    holder: str
    verifiableCredential: list[VerifiableCredential] = Field(default_factory=list)


class VerifiedSubject(BaseModel):
    """Identity and claims established by verifying a presentation."""

    did: str
    claims: dict[str, Any] = Field(default_factory=dict)
    credential_types: list[str] = Field(default_factory=list)


class PresentationVerifier:
    """Verifies presentations against a set of trusted issuers."""

    def __init__(
        self,
        resolver: DIDResolver,
        http: httpx.Client,
        trusted_issuers: set[str],
        max_age: timedelta = timedelta(minutes=5),
    ):
        self.resolver = resolver
        self.http = http
        self.trusted_issuers = trusted_issuers
        self.max_age = max_age
        self._seen: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def verify(self, vp: VerifiablePresentation, audience: str,
               expected_holder: str | None = None) -> VerifiedSubject:
        if expected_holder and vp.holder != expected_holder:
            raise Unauthenticated(f"presentation holder {vp.holder} is not {expected_holder}")
        self.resolver.verify(vp, expected_signer=vp.holder, purpose="authentication")
        proof = vp.proof
        assert proof is not None
        if proof.domain != audience:
            raise Unauthenticated(f"presentation is addressed to {proof.domain}, not {audience}")
        now = utcnow()
        if not (now - self.max_age <= proof.created <= now + timedelta(seconds=30)):
            raise Unauthenticated("presentation is stale")
        self._check_replay(vp.holder, proof.challenge, now)

        subject = VerifiedSubject(did=vp.holder)
        for vc in vp.verifiableCredential:
            self.verify_credential(vc, vp.holder, now)
            subject.credential_types += [t for t in vc.type if t != "VerifiableCredential"]
            for key, value in vc.credentialSubject.items():
                if key == "id":
                    continue
                previous = subject.claims.get(key)
                if isinstance(previous, list) and isinstance(value, list):
                    value = sorted(set(previous) | set(value))
                subject.claims[key] = value
        return subject

    def verify_credential(self, vc: VerifiableCredential, holder: str, now: datetime | None = None) -> None:
        now = now or utcnow()
        if vc.issuer not in self.trusted_issuers:
            raise Unauthenticated(f"credential {vc.id} issued by untrusted issuer {vc.issuer}")
        self.resolver.verify(vc, expected_signer=vc.issuer)
        if vc.subject != holder:
            raise Unauthenticated(f"credential {vc.id} was issued to {vc.subject}, not {holder}")
        if vc.validFrom > now or (vc.validUntil and vc.validUntil < now):
            raise Unauthenticated(f"credential {vc.id} is not valid at this time")
        if vc.credentialStatus and vc.id in self._revoked(vc.credentialStatus.id, vc.issuer):
            raise Unauthenticated(f"credential {vc.id} has been revoked")

    def _revoked(self, url: str, issuer: str) -> set[str]:
        try:
            status = RevocationList.model_validate(call(self.http, "GET", url).json())
        except DataSpaceError as exc:
            raise Unauthenticated(f"cannot check revocation status: {exc.detail}") from exc
        self.resolver.verify(status, expected_signer=issuer)
        return set(status.revoked)

    def _check_replay(self, holder: str, challenge: str | None, now: datetime) -> None:
        if not challenge:
            raise Unauthenticated("presentation has no challenge")
        with self._lock:
            self._seen = {k: t for k, t in self._seen.items() if t > now - self.max_age}
            if (holder, challenge) in self._seen:
                raise Unauthenticated("presentation replayed")
            self._seen[(holder, challenge)] = now


def issue_credential(
    issuer: str,
    sign,
    subject: str,
    types: list[str],
    claims: dict[str, Any],
    valid_for: timedelta,
    status_url: str | None = None,
) -> VerifiableCredential:
    """Create and sign a credential; ``sign`` is a ``Wallet.sign``-like callable."""
    now = utcnow()
    vc = VerifiableCredential(
        type=["VerifiableCredential", *types],
        issuer=issuer,
        validFrom=now,
        validUntil=now + valid_for,
        credentialSubject={"id": subject, **claims},
        credentialStatus=CredentialStatus(id=status_url) if status_url else None,
    )
    vc.proof = sign(vc.signing_payload())
    return vc
