import pytest

from dataspace.identity.credentials import VerifiedSubject
from dataspace.sim import LocalDataSpace

CLINICAL = "clinical-records-2024"
MOBILITY = "urban-mobility-2024"


@pytest.fixture
def space() -> LocalDataSpace:
    """A fresh data space: authority, catalog, log and connectors A (hospital), B (EU lab), C (US company)."""
    return LocalDataSpace().start()


@pytest.fixture
def hospital(space):
    return space.clients["participant_a"]


@pytest.fixture
def lab(space):
    return space.clients["participant_b"]


@pytest.fixture
def corp(space):
    return space.clients["participant_c"]


def subject(did: str = "did:web:example", **claims) -> VerifiedSubject:
    return VerifiedSubject(did=did, claims=claims)
