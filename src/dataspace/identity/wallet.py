"""Identity wallet of a service: its DID, signing key and credentials."""

from __future__ import annotations

import secrets
from typing import Any

from dataspace.common.crypto import KeyPair
from dataspace.identity.credentials import VerifiableCredential, VerifiablePresentation
from dataspace.identity.did import DIDDocument
from dataspace.identity.proofs import Proof, Signed, create_proof


class Wallet:
    def __init__(self, did: str, keys: KeyPair):
        self.did = did
        self.keys = keys
        self.credentials: list[VerifiableCredential] = []

    @property
    def key_id(self) -> str:
        return f"{self.did}#key-1"

    def did_document(self, services: dict[str, str] | None = None) -> DIDDocument:
        return DIDDocument.for_key(self.did, self.keys.public_jwk, services)

    def sign(self, payload: dict[str, Any], purpose: str = "assertionMethod",
             challenge: str | None = None, domain: str | None = None) -> Proof:
        return create_proof(payload, self.keys, self.key_id, purpose, challenge, domain)

    def sign_document(self, document: Signed) -> Signed:
        document.proof = self.sign(document.signing_payload())
        return document

    def present(self, audience: str, credentials: list[VerifiableCredential] | None = None) -> VerifiablePresentation:
        """Build a fresh presentation bound to ``audience`` (replay-protected by a random challenge)."""
        vp = VerifiablePresentation(
            holder=self.did,
            verifiableCredential=self.credentials if credentials is None else credentials,
        )
        vp.proof = self.sign(
            vp.signing_payload(), purpose="authentication",
            challenge=secrets.token_urlsafe(16), domain=audience,
        )
        return vp
