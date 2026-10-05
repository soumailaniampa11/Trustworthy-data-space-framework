"""Decentralised identity: DIDs, verifiable credentials and presentations."""

from dataspace.identity.credentials import (
    PresentationVerifier,
    RevocationList,
    VerifiableCredential,
    VerifiablePresentation,
    VerifiedSubject,
    issue_credential,
)
from dataspace.identity.did import DIDDocument, DIDResolver, did_web, did_web_to_url
from dataspace.identity.proofs import Proof, Signed, check_proof, create_proof
from dataspace.identity.wallet import Wallet

__all__ = [
    "DIDDocument", "DIDResolver", "PresentationVerifier", "Proof", "RevocationList", "Signed",
    "VerifiableCredential", "VerifiablePresentation", "VerifiedSubject", "Wallet",
    "check_proof", "create_proof", "did_web", "did_web_to_url", "issue_credential",
]
