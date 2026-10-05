from datetime import timedelta

import pytest

from dataspace.core.exceptions import AlreadyExistsError, AuthenticationError, NotFoundError
from dataspace.identity import (
    IdentityProvider,
    KeyPair,
    Participant,
    ParticipantRegistry,
    ParticipantStatus,
    verify_signature,
)


@pytest.fixture
def setup():
    registry = ParticipantRegistry()
    keys = KeyPair()
    registry.register(Participant(id="a", name="A", organization="A", public_key=keys.public_key))
    return registry, IdentityProvider(registry), keys


def test_signature_roundtrip():
    keys = KeyPair()
    sig = keys.sign(b"hello")
    assert verify_signature(keys.public_key, b"hello", sig)
    assert not verify_signature(keys.public_key, b"tampered", sig)
    assert not verify_signature(KeyPair().public_key, b"hello", sig)


def test_registry_rejects_duplicates_and_unknown(setup):
    registry, _, keys = setup
    with pytest.raises(AlreadyExistsError):
        registry.register(Participant(id="a", name="A", organization="A", public_key=keys.public_key))
    with pytest.raises(NotFoundError):
        registry.get("ghost")


def test_challenge_response_issues_valid_token(setup):
    _, idp, keys = setup
    challenge = idp.create_challenge("a")
    token = idp.authenticate("a", keys.sign(challenge.encode()))
    assert idp.verify_token(token).id == "a"


def test_wrong_key_is_rejected(setup):
    _, idp, _ = setup
    challenge = idp.create_challenge("a")
    with pytest.raises(AuthenticationError, match="invalid challenge signature"):
        idp.authenticate("a", KeyPair().sign(challenge.encode()))


def test_challenge_is_single_use(setup):
    _, idp, keys = setup
    challenge = idp.create_challenge("a")
    signature = keys.sign(challenge.encode())
    idp.authenticate("a", signature)
    with pytest.raises(AuthenticationError, match="no pending challenge"):
        idp.authenticate("a", signature)


def test_forged_token_is_rejected(setup):
    _, idp, keys = setup
    token = idp.authenticate("a", keys.sign(idp.create_challenge("a").encode()))
    payload, signature = token.split(".")
    forged_payload = payload[:-4] + ("AAAA" if payload[-4:] != "AAAA" else "BBBB")
    with pytest.raises(AuthenticationError):
        idp.verify_token(f"{forged_payload}.{signature}")
    other = IdentityProvider(idp.registry)
    with pytest.raises(AuthenticationError, match="invalid token signature"):
        other.verify_token(token)


def test_expired_and_revoked_tokens(setup):
    registry, _, keys = setup
    idp = IdentityProvider(registry, token_ttl=timedelta(seconds=-1))
    token = idp.authenticate("a", keys.sign(idp.create_challenge("a").encode()))
    with pytest.raises(AuthenticationError, match="expired"):
        idp.verify_token(token)

    idp = IdentityProvider(registry)
    token = idp.authenticate("a", keys.sign(idp.create_challenge("a").encode()))
    idp.revoke_token(token)
    with pytest.raises(AuthenticationError, match="revoked"):
        idp.verify_token(token)


def test_suspended_participant_cannot_use_token(setup):
    registry, idp, keys = setup
    token = idp.authenticate("a", keys.sign(idp.create_challenge("a").encode()))
    registry.set_status("a", ParticipantStatus.SUSPENDED)
    with pytest.raises(AuthenticationError, match="suspended"):
        idp.verify_token(token)
