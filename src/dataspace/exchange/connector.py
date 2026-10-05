"""Participant connector (data plane).

Each participant runs a connector that keeps its data locally. Data only
leaves the connector through a transfer backed by a valid grant, and every
payload is signed so consumers can verify its provenance.
"""

from __future__ import annotations

from dataspace.catalog.dataset import sha256
from dataspace.core.exceptions import IntegrityError, NotFoundError
from dataspace.identity.participant import KeyPair, verify_signature


class Connector:
    def __init__(self, participant_id: str, keys: KeyPair | None = None):
        self.participant_id = participant_id
        self._keys = keys or KeyPair()
        self._storage: dict[str, bytes] = {}
        self._received: dict[str, bytes] = {}

    @property
    def public_key(self) -> str:
        return self._keys.public_key

    # provider side
    def store(self, dataset_id: str, data: bytes) -> str:
        self._storage[dataset_id] = data
        return sha256(data)

    def has(self, dataset_id: str) -> bool:
        return dataset_id in self._storage

    def provide(self, dataset_id: str) -> tuple[bytes, str]:
        """Return the data and a signature over its checksum."""
        try:
            data = self._storage[dataset_id]
        except KeyError:
            raise NotFoundError(f"connector of '{self.participant_id}' has no '{dataset_id}'") from None
        return data, self._keys.sign(sha256(data).encode())

    # consumer side
    def receive(
        self, transfer_id: str, data: bytes, expected_checksum: str, signature: str, provider_key: str
    ) -> None:
        checksum = sha256(data)
        if checksum != expected_checksum:
            raise IntegrityError("checksum mismatch: data differs from the catalog offer")
        if not verify_signature(provider_key, checksum.encode(), signature):
            raise IntegrityError("invalid provider signature")
        self._received[transfer_id] = data

    def received(self, transfer_id: str) -> bytes:
        try:
            return self._received[transfer_id]
        except KeyError:
            raise NotFoundError(f"no received data for transfer '{transfer_id}'") from None
