"""Decentralised identifiers using the ``did:web`` method.

``did:web:connector-a%3A8000`` resolves to
``<scheme>://connector-a:8000/.well-known/did.json``. Every participant hosts
its own DID document: there is no central identity provider.
"""

from __future__ import annotations

import time
from urllib.parse import quote, unquote, urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field

from dataspace.common.errors import DataSpaceError, Unauthenticated
from dataspace.common.http import call
from dataspace.identity.proofs import Proof, Signed, check_proof


def did_web(base_url: str) -> str:
    parsed = urlparse(base_url)
    parts = [quote(parsed.netloc, safe="")] + [p for p in parsed.path.split("/") if p]
    return "did:web:" + ":".join(parts)


def did_web_to_url(did: str, scheme: str = "https") -> str:
    if not did.startswith("did:web:"):
        raise Unauthenticated(f"unsupported DID method: {did}")
    host, *path = did[len("did:web:"):].split(":")
    return f"{scheme}://{unquote(host)}" + "".join(f"/{p}" for p in path)


class VerificationMethod(BaseModel):
    id: str
    type: str = "JsonWebKey2020"
    controller: str
    publicKeyJwk: dict[str, str]


class Service(BaseModel):
    id: str
    type: str
    serviceEndpoint: str


class DIDDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    context: list[str] = Field(
        default_factory=lambda: ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jws/v1"],
        alias="@context",
    )
    id: str
    verificationMethod: list[VerificationMethod]
    authentication: list[str]
    assertionMethod: list[str]
    service: list[Service] = Field(default_factory=list)

    @classmethod
    def for_key(cls, did: str, public_jwk: dict[str, str], services: dict[str, str] | None = None) -> DIDDocument:
        key_id = f"{did}#key-1"
        return cls(
            id=did,
            verificationMethod=[VerificationMethod(id=key_id, controller=did, publicKeyJwk=public_jwk)],
            authentication=[key_id],
            assertionMethod=[key_id],
            service=[
                Service(id=f"{did}#{kind}", type=kind, serviceEndpoint=url)
                for kind, url in (services or {}).items()
            ],
        )

    def public_key(self, method_id: str, purpose: str) -> str:
        allowed = self.authentication if purpose == "authentication" else self.assertionMethod
        if method_id not in allowed:
            raise Unauthenticated(f"{method_id} is not authorised for {purpose}")
        for method in self.verificationMethod:
            if method.id == method_id:
                return method.publicKeyJwk["x"]
        raise Unauthenticated(f"verification method {method_id} not found")

    def endpoint(self, kind: str) -> str | None:
        return next((s.serviceEndpoint for s in self.service if s.type == kind), None)


class DIDResolver:
    def __init__(self, http: httpx.Client, scheme: str = "https", cache_seconds: float = 60):
        self.http = http
        self.scheme = scheme
        self.cache_seconds = cache_seconds
        self._cache: dict[str, tuple[DIDDocument, float]] = {}

    def resolve(self, did: str) -> DIDDocument:
        cached = self._cache.get(did)
        if cached and time.monotonic() - cached[1] < self.cache_seconds:
            return cached[0]
        url = did_web_to_url(did, self.scheme) + "/.well-known/did.json"
        try:
            document = DIDDocument.model_validate(call(self.http, "GET", url).json())
        except DataSpaceError as exc:
            raise Unauthenticated(f"cannot resolve {did}: {exc.detail}") from exc
        if document.id != did:
            raise Unauthenticated(f"DID document at {url} is for {document.id}")
        self._cache[did] = (document, time.monotonic())
        return document

    def verify(self, document: Signed, expected_signer: str | None = None,
               purpose: str = "assertionMethod", proof: Proof | None = None) -> str:
        """Check ``document``'s proof; return the signer DID or raise ``Unauthenticated``."""
        proof = proof or document.proof
        if proof is None:
            raise Unauthenticated("document is not signed")
        if expected_signer and proof.controller != expected_signer:
            raise Unauthenticated(f"signed by {proof.controller}, expected {expected_signer}")
        if proof.proofPurpose != purpose:
            raise Unauthenticated(f"proof purpose is {proof.proofPurpose}, expected {purpose}")
        key = self.resolve(proof.controller).public_key(proof.verificationMethod, purpose)
        if not check_proof(document.signing_payload(), proof, key):
            raise Unauthenticated(f"invalid signature by {proof.controller}")
        return proof.controller
