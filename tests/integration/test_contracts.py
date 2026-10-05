"""Contract negotiation: policy decisions and bilateral signed agreements."""

import pytest

from dataspace.common.errors import IntegrityViolation
from dataspace.protocol.negotiation import ContractAgreement, ContractRequest, NegotiationState
from tests.conftest import CLINICAL, MOBILITY


def test_eligible_consumer_obtains_bilaterally_signed_agreement(space, lab, hospital):
    negotiation = lab.negotiate(space.did("participant_a"), CLINICAL, "read", "research")
    assert negotiation.state == NegotiationState.FINALIZED
    agreement = negotiation.agreement
    assert [d.action for d in agreement.obligations] == ["delete", "attribute"]

    resolver = space.control_planes["participant_b"].ctx.resolver
    assert resolver.verify(agreement, expected_signer=space.did("participant_a")) == agreement.provider
    assert resolver.verify(agreement, expected_signer=space.did("participant_b"),
                           proof=agreement.consumer_proof) == agreement.consumer
    provider_copy = hospital.agreements()["as_provider"][0]["agreement"]
    assert ContractAgreement.model_validate(provider_copy) == agreement  # both hold the same contract


@pytest.mark.parametrize("participant, action, purpose, reason", [
    ("participant_c", "read", "research", "participant.region eq 'EU'"),
    ("participant_c", "read", "research", "participant.certifications hasPart 'iso27001'"),
    ("participant_b", "read", "marketing", "purpose isAnyOf"),
    ("participant_b", "reproduce", "research", "prohibited by rule no-copy-no-redistribution"),
    ("participant_b", "modify", "research", "no rule permits 'modify'"),
])
def test_ineligible_requests_are_terminated_with_reason(space, participant, action, purpose, reason):
    negotiation = space.clients[participant].negotiate(space.did("participant_a"), CLINICAL, action, purpose)
    assert negotiation.state == NegotiationState.TERMINATED
    assert reason in negotiation.reason
    assert negotiation.agreement is None


def test_open_data_is_available_to_any_member(space, corp):
    negotiation = corp.negotiate(space.did("participant_b"), MOBILITY, "reproduce")
    assert negotiation.state == NegotiationState.FINALIZED


def test_outdated_offer_is_refused(space, lab, hospital):
    lab_cp = space.control_planes["participant_b"]
    offer = lab_cp.catalog("clinical")[0]
    hospital.set_policy(CLINICAL, [])  # v2 published after the consumer read v1
    request = ContractRequest(negotiation_id="neg-old", consumer=lab_cp.did, dataset_id=CLINICAL,
                              policy_uid=offer.policy["uid"], action="read", purpose="research",
                              presentation=lab_cp.ctx.wallet.present(offer.provider))
    response = space.control_planes["participant_a"].handle_contract_request(request)
    assert response.state == NegotiationState.TERMINATED and "outdated" in response.reason


def test_consumer_rejects_agreement_that_differs_from_request(space):
    lab_cp = space.control_planes["participant_b"]
    provider_cp = space.control_planes["participant_a"]
    offer = lab_cp.catalog("clinical")[0]
    request = ContractRequest(negotiation_id="neg-y", consumer=lab_cp.did, dataset_id=CLINICAL,
                              policy_uid=offer.policy["uid"], action="read", purpose="research",
                              presentation=lab_cp.ctx.wallet.present(offer.provider))
    agreement = provider_cp.handle_contract_request(request).agreement
    agreement.purpose = "marketing"  # widened terms: provider signature no longer valid
    with pytest.raises(Exception, match="invalid signature"):
        lab_cp._check_agreement(agreement, request, offer)
    provider_cp.ctx.wallet.sign_document(agreement)  # validly signed but not what was asked
    with pytest.raises(IntegrityViolation, match="purpose"):
        lab_cp._check_agreement(agreement, request, offer)
