from datetime import timedelta

import pytest

from dataspace.access import GrantStatus, RequestStatus
from dataspace.audit import AuditLogger, Outcome
from dataspace.core.exceptions import AuthorizationError, IntegrityError, PolicyViolationError
from dataspace.policy import Rule


def test_eu_research_request_is_granted_with_obligations(space):
    request = space.request_access("lab", "records", "read", purpose="research")
    assert request.status == RequestStatus.GRANTED
    grant = space.authz.get_grant(request.grant_id)
    assert grant.provider_id == "hospital" and grant.consumer_id == "lab"
    assert [d.action for d in grant.obligations] == ["delete_after"]


@pytest.mark.parametrize(
    "consumer, action, purpose, reason",
    [
        ("corp", "read", "research", "participant.country"),
        ("lab", "read", "marketing", "purpose eq 'research'"),
        ("lab", "share", "research", "prohibited by rule no-share"),
        ("lab", "download", "research", "no rule permits"),
    ],
)
def test_requests_violating_policy_are_denied(space, consumer, action, purpose, reason):
    request = space.request_access(consumer, "records", action, purpose=purpose)
    assert request.status == RequestStatus.DENIED
    assert reason in request.reason
    assert space.audit.query(actor=consumer, outcome=Outcome.DENIED)


def test_provider_only_role_cannot_consume(space):
    assert space.request_access("hospital", "records", "read", "research").status == RequestStatus.DENIED


def test_max_uses_exhausts_grant(space):
    grant_id = space.request_access("lab", "records", "read", "research", max_uses=1).grant_id
    lab = space.registry.get("lab")
    space.authz.use_grant(grant_id, lab)
    with pytest.raises(AuthorizationError, match="exhausted"):
        space.authz.use_grant(grant_id, lab)


def test_expired_grant_is_rejected(space):
    lab = space.registry.get("lab")
    request = space.authz.request_access(lab, "records", "read", "research", ttl=timedelta(seconds=-1))
    with pytest.raises(AuthorizationError, match="expired"):
        space.authz.use_grant(request.grant_id, lab)


def test_grant_cannot_be_used_by_another_participant(space):
    grant_id = space.request_access("lab", "records", "read", "research").grant_id
    with pytest.raises(AuthorizationError, match="another participant"):
        space.authz.use_grant(grant_id, space.registry.get("corp"))


def test_policy_change_revokes_existing_grants(space):
    """Continuous usage control: a stricter policy applies to grants already issued."""
    grant_id = space.request_access("lab", "records", "read", "research").grant_id
    space.set_policy("hospital", "records", [Rule(actions=["read"], assignees=["someone-else"])])
    with pytest.raises(PolicyViolationError):
        space.authz.use_grant(grant_id, space.registry.get("lab"))
    assert space.authz.get_grant(grant_id).status == GrantStatus.REVOKED


def test_attribute_change_revokes_existing_grants(space):
    grant_id = space.request_access("lab", "records", "read", "research").grant_id
    space.registry.get("lab").attributes["country"] = "US"
    with pytest.raises(PolicyViolationError):
        space.authz.use_grant(grant_id, space.registry.get("lab"))


def test_provider_can_revoke_but_third_party_cannot(space):
    grant_id = space.request_access("lab", "records", "read", "research").grant_id
    with pytest.raises(AuthorizationError):
        space.authz.revoke_grant(grant_id, "corp")
    assert space.authz.revoke_grant(grant_id, "hospital").status == GrantStatus.REVOKED


def test_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(path)
    for i in range(3):
        log.log("a", "event", f"r{i}")
    assert AuditLogger.load(path).verify()

    log._events[1].details["forged"] = True
    with pytest.raises(IntegrityError, match="event 1 was modified"):
        log.verify()

    log = AuditLogger.load(path)
    del log._events[1]
    with pytest.raises(IntegrityError):
        log.verify()
