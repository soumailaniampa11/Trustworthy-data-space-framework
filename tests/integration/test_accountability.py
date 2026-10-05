"""Accountability: local hash chains anchored in the Merkle transparency log."""

import pytest

from dataspace.audit.chain import Outcome
from dataspace.audit.receipts import SignedTreeHead
from dataspace.common.errors import IntegrityViolation
from tests.conftest import CLINICAL


def test_every_event_is_anchored_and_provably_included(space, lab, hospital):
    agreement = lab.negotiate(space.did("participant_a"), CLINICAL, "read", "research").agreement
    lab.transfer(agreement.id)
    for client in (lab, hospital):
        report = client.verify_audit()
        assert report["events"] == report["anchored"] == report["verified_inclusions"] > 0


def test_both_parties_log_the_same_contract(space, lab, hospital):
    agreement = lab.negotiate(space.did("participant_a"), CLINICAL, "read", "research").agreement
    consumer_digest = next(e for e in lab.audit() if e.event_type == "contract.negotiated").details["digest"]
    provider_digest = next(e for e in hospital.audit() if e.event_type == "contract.finalized").details["digest"]
    assert consumer_digest == provider_digest
    assert agreement.id in str(hospital.audit()[-1].details)


def test_denials_are_recorded_by_the_provider(space, corp, hospital):
    corp.negotiate(space.did("participant_a"), CLINICAL, "read", "research")
    denied = [e for e in hospital.audit() if e.outcome == "denied"]
    assert denied and denied[-1].actor == space.did("participant_c")
    assert denied[-1].details["claims"]["country"] == "US"


def test_local_rewrite_is_detected(space, hospital):
    store = space.control_planes["participant_a"].ctx.store
    event = space.control_planes["participant_a"].audit.events()[0]
    event.outcome = Outcome.DENIED
    store.put("audit", "0", event)
    with pytest.raises(IntegrityViolation, match="event 0 was modified"):
        hospital.verify_audit()


def test_operator_recomputing_the_chain_is_caught_by_the_log(space, hospital):
    """Rewriting an event *and* recomputing every hash keeps the chain valid, but not the anchors."""
    cp = space.control_planes["participant_a"]
    events = cp.audit.events()
    events[0].details["checksum"] = "forged"
    previous = "0" * 64
    for event in events:
        event.previous_hash = previous
        event.hash = event.compute_hash()
        previous = event.hash
        cp.ctx.store.put("audit", str(event.sequence), event)
    cp.audit.verify()  # locally consistent...
    with pytest.raises(IntegrityViolation, match="does not commit to event 0"):
        hospital.verify_audit()  # ...but contradicts the public log


def test_log_history_rewrite_is_detected(space, lab):
    lab.verify_audit()
    cp = space.control_planes["participant_b"]
    seen = cp.ctx.store.get("tree_heads", "latest", SignedTreeHead)
    seen.root_hash = "00" * 32  # the log later presents a different past
    cp.ctx.store.put("tree_heads", "latest", seen)
    lab.negotiate(space.did("participant_a"), CLINICAL, "read", "research")
    with pytest.raises(IntegrityViolation, match="rewritten"):
        lab.verify_audit()
