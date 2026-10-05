"""Transfers: continuous usage control, integrity and provenance of data."""

import pytest

from dataspace.common.crypto import sha256_hex
from dataspace.common.errors import Forbidden, IntegrityViolation, PolicyViolation
from dataspace.policy import Constraint, Rule
from dataspace.protocol.transfer import TransferRequest, TransferState
from tests.conftest import CLINICAL


@pytest.fixture
def agreement(space, lab):
    return lab.negotiate(space.did("participant_a"), CLINICAL, "read", "research").agreement


def test_transfer_delivers_verified_data(space, lab, agreement):
    transfer = lab.transfer(agreement.id)
    data = lab.data(transfer.id)
    assert transfer.state == TransferState.COMPLETED
    assert data.startswith(b"patient_pseudo_id") and sha256_hex(data) == agreement.checksum


def test_policy_change_applies_to_existing_agreements(space, lab, hospital, agreement):
    lab.transfer(agreement.id)
    hospital.set_policy(CLINICAL, [Rule(id="france-only", actions=["read"], constraints=[
        Constraint(left_operand="participant.country", operator="eq", right_operand="FR")])])
    with pytest.raises(PolicyViolation, match="france-only"):
        lab.transfer(agreement.id)


def test_usage_limit_is_enforced_across_transfers(space, lab, hospital, agreement):
    hospital.set_policy(CLINICAL, [Rule(id="twice", actions=["read"], constraints=[
        Constraint(left_operand="usage_count", operator="lt", right_operand=2)])])
    lab.transfer(agreement.id)
    lab.transfer(agreement.id)
    with pytest.raises(PolicyViolation, match="usage_count lt 2"):
        lab.transfer(agreement.id)


def test_revoked_agreement_cannot_be_used(space, lab, hospital, agreement):
    hospital.revoke(agreement.id, "breach of duty 'delete'")
    with pytest.raises(Forbidden, match="breach of duty"):
        lab.transfer(agreement.id)


def test_withdrawn_dataset_stops_transfers(space, lab, hospital, agreement):
    hospital.withdraw(CLINICAL)
    with pytest.raises(Forbidden, match="withdrawn"):
        lab.transfer(agreement.id)


def test_agreement_cannot_be_used_by_another_participant(space, agreement):
    corp = space.control_planes["participant_c"]
    corp.ctx.store.put("contracts", agreement.id, agreement)  # stolen copy of the contract
    with pytest.raises(Forbidden, match="another participant"):
        corp.transfer(agreement.id)


def test_tampered_provider_data_is_detected(space, lab, agreement):
    provider = space.control_planes["participant_a"]
    provider.blobs.put(f"datasets/{CLINICAL}", b"forged content")
    with pytest.raises(IntegrityViolation, match="differs from the data agreed"):
        lab.transfer(agreement.id)
    failed = [e for e in lab.audit() if e.event_type == "transfer.received"][-1]
    assert failed.outcome == "failure" and failed.details["error"] == "IntegrityViolation"


def test_data_address_is_single_use(space, agreement):
    lab_cp = space.control_planes["participant_b"]
    provider = space.control_planes["participant_a"]
    response = provider.handle_transfer_request(TransferRequest(
        transfer_id="tx-1", agreement_id=agreement.id, consumer=lab_cp.did,
        presentation=lab_cp.ctx.wallet.present(provider.did)))
    lab_cp._pull(response.data_address)
    with pytest.raises(Forbidden, match="already used"):
        lab_cp._pull(response.data_address)
