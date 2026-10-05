"""Data Integrity proofs over JSON documents.

Modelled on the W3C ``DataIntegrityProof`` with the ``eddsa-jcs-2022``
cryptosuite: the signing input is the JCS-canonicalised document together
with the proof options, signed with Ed25519. (Simplification: the document
and proof options are signed jointly rather than hashed separately.)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from dataspace.common.clock import utcnow
from dataspace.common.crypto import KeyPair, canonical_json, verify


class Proof(BaseModel):
    type: str = "DataIntegrityProof"
    cryptosuite: str = "eddsa-jcs-2022"
    created: datetime
    verificationMethod: str
    proofPurpose: str = "assertionMethod"
    challenge: str | None = None
    domain: str | None = None
    proofValue: str = ""

    @property
    def controller(self) -> str:
        """DID that controls the signing key (``did:...#key-1`` -> ``did:...``)."""
        return self.verificationMethod.split("#", 1)[0]


class Signed(BaseModel):
    """Base class for documents carrying a single ``proof``."""

    model_config = ConfigDict(populate_by_name=True)

    proof: Proof | None = None

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude={"proof"}, exclude_none=True)


def _signing_input(payload: dict[str, Any], proof: Proof) -> bytes:
    options = proof.model_dump(mode="json", exclude={"proofValue"}, exclude_none=True)
    return canonical_json({"document": payload, "proof": options})


def create_proof(
    payload: dict[str, Any],
    keys: KeyPair,
    verification_method: str,
    purpose: str = "assertionMethod",
    challenge: str | None = None,
    domain: str | None = None,
) -> Proof:
    proof = Proof(
        created=utcnow(), verificationMethod=verification_method, proofPurpose=purpose,
        challenge=challenge, domain=domain,
    )
    proof.proofValue = keys.sign(_signing_input(payload, proof))
    return proof


def check_proof(payload: dict[str, Any], proof: Proof, public_key: str) -> bool:
    return verify(public_key, _signing_input(payload, proof), proof.proofValue)
