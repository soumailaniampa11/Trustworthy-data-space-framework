"""Verifiable identity: only claims attested by a trusted issuer count."""

from datetime import timedelta

import pytest

from dataspace.common.crypto import KeyPair
from dataspace.common.clock import utcnow
from dataspace.common.errors import NotFound, Unauthenticated
from dataspace.common.http import call
from dataspace.identity import Wallet, did_web, issue_credential
from dataspace.protocol.catalog import DatasetOffer
from dataspace.protocol.negotiation import ContractRequest, NegotiationState
from tests.conftest import CLINICAL, MOBILITY


def test_participants_hold_attested_credentials(space, lab):
    identity = lab.identity()
    types = {t for vc in identity["credentials"] for t in vc["type"]}
    assert {"MembershipCredential", "JurisdictionCredential", "CertificationCredential"} <= types
    assert all(vc["issuer"] == space.authority_did for vc in identity["credentials"])


def test_unregistered_entity_gets_no_credentials(space):
    stranger = Wallet(did_web("http://connector-a:8000"), KeyPair())  # claims A's DID, wrong key
    vp = stranger.present(space.authority_did, credentials=[])
    with pytest.raises(Unauthenticated, match="invalid signature"):
        call(space.http, "POST", "http://authority:8000/credentials/request",
             json=vp.model_dump(mode="json", by_alias=True, exclude_none=True))


def test_self_issued_credential_is_rejected(space, hospital):
    """C issues itself an EU jurisdiction credential: the provider ignores untrusted issuers."""
    corp = space.control_planes["participant_c"]
    fake = issue_credential(corp.did, corp.ctx.wallet.sign, corp.did, ["JurisdictionCredential"],
                            {"region": "EU", "certifications": ["iso27001"]}, timedelta(days=1))
    request = ContractRequest(
        negotiation_id="neg-fake", consumer=corp.did, dataset_id=CLINICAL,
        policy_uid=f"urn:policy:{CLINICAL}:v1", action="read", purpose="research",
        presentation=corp.ctx.wallet.present(space.did("participant_a"), credentials=[fake]),
    )
    with pytest.raises(Unauthenticated, match="untrusted issuer"):
        space.control_planes["participant_a"].handle_contract_request(request)


def test_presentation_bound_to_audience_and_not_replayable(space):
    lab = space.control_planes["participant_b"]
    provider = space.control_planes["participant_a"]

    def request(vp):
        return ContractRequest(negotiation_id="neg-x", consumer=lab.did, dataset_id=CLINICAL,
                               policy_uid=f"urn:policy:{CLINICAL}:v1", action="read",
                               purpose="research", presentation=vp)

    with pytest.raises(Unauthenticated, match="addressed to"):
        provider.handle_contract_request(request(lab.ctx.wallet.present(space.did("participant_c"))))

    vp = lab.ctx.wallet.present(provider.did)
    assert provider.handle_contract_request(request(vp)).state == NegotiationState.AGREED
    with pytest.raises(Unauthenticated, match="replayed"):
        provider.handle_contract_request(request(vp))


def test_revoked_credentials_block_access(space, lab, hospital):
    agreement = lab.negotiate(space.did("participant_a"), CLINICAL, "read", "research").agreement
    space.revoke_credentials("participant_b")
    with pytest.raises(Unauthenticated, match="revoked"):
        lab.transfer(agreement.id)
    with pytest.raises(Unauthenticated, match="revoked"):
        lab.negotiate(space.did("participant_b"), MOBILITY, "read")


def test_management_api_requires_key(space):
    with pytest.raises(Unauthenticated):
        call(space.http, "GET", "http://connector-a:8000/management/datasets",
             headers={"X-Api-Key": "wrong"})


def test_withdrawn_offer_cannot_be_negotiated(space, lab, hospital):
    hospital.withdraw(CLINICAL)
    assert CLINICAL not in [o.id for o in lab.catalog()]
    with pytest.raises(NotFound):
        lab.negotiate(space.did("participant_a"), CLINICAL, "read", "research")


def test_unresolvable_provider_cannot_publish_offers(space):
    rogue = Wallet(did_web("http://rogue:8000"), KeyPair())
    offer = DatasetOffer(id="x", title="x", byte_size=1, checksum="0", provider=rogue.did,
                         endpoint="http://rogue:8000/dsp", policy={}, issued=utcnow())
    rogue.sign_document(offer)
    with pytest.raises(Unauthenticated):  # its DID cannot even be resolved
        call(space.http, "POST", "http://catalog:8000/offers", json=offer.model_dump(mode="json"))


def test_offer_endpoint_must_match_provider_did_document(space):
    hospital = space.control_planes["participant_a"]
    offer = hospital.catalog("clinical")[0]
    offer.endpoint = "http://attacker:8000/dsp"  # redirect consumers to a fake connector
    offer.issued = utcnow()
    hospital.ctx.wallet.sign_document(offer)
    with pytest.raises(Unauthenticated, match="endpoint"):
        call(space.http, "POST", "http://catalog:8000/offers", json=offer.model_dump(mode="json"))
