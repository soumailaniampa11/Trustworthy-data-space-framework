"""Cryptographic primitives: Ed25519 keys, canonical JSON, hashing.

Canonicalisation follows the JSON Canonicalization Scheme (RFC 8785) for the
value types used in this framework (strings, integers, booleans, lists,
objects): keys sorted, no insignificant whitespace, UTF-8.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class KeyPair:
    """Ed25519 key pair. The private key never leaves its holder."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._private = private_key or Ed25519PrivateKey.generate()

    @classmethod
    def load_or_create(cls, path: str | Path | None) -> KeyPair:
        """Load a PEM key from ``path``, creating it on first use (``None``: ephemeral)."""
        if path is None:
            return cls()
        path = Path(path)
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            assert isinstance(key, Ed25519PrivateKey)
            return cls(key)
        keys = cls()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            keys._private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        return keys

    @property
    def public_key(self) -> str:
        """Raw public key, base64url-encoded (the ``x`` member of an OKP JWK)."""
        raw = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return b64url_encode(raw)

    @property
    def public_jwk(self) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "x": self.public_key}

    def sign(self, message: bytes) -> str:
        return b64url_encode(self._private.sign(message))


def verify(public_key: str, message: bytes, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64url_decode(public_key)).verify(
            b64url_decode(signature), message
        )
        return True
    except (InvalidSignature, ValueError):
        return False
