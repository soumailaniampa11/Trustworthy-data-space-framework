"""Access control service (policy enforcement point).

Access is decided twice:

* at request time, producing an :class:`AccessGrant` if the policy allows it;
* at every use of the grant (continuous usage control), so that revoked
  grants, expired time windows, changed participant attributes or updated
  policies take effect immediately.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from dataspace.access.request import AccessGrant, AccessRequest, GrantStatus, RequestStatus
from dataspace.audit.logger import AuditLogger, Outcome
from dataspace.catalog.catalog import Catalog
from dataspace.core.exceptions import AuthorizationError, NotFoundError, PolicyViolationError
from dataspace.identity.participant import Participant, Role
from dataspace.policy.evaluator import Decision, EvaluationContext, PolicyEvaluator
from dataspace.policy.policy import Action, PolicyStore


class AuthorizationService:
    def __init__(
        self,
        catalog: Catalog,
        policies: PolicyStore,
        audit: AuditLogger,
        evaluator: PolicyEvaluator | None = None,
        default_grant_ttl: timedelta | None = timedelta(days=1),
    ):
        self.catalog = catalog
        self.policies = policies
        self.audit = audit
        self.evaluator = evaluator or PolicyEvaluator()
        self.default_grant_ttl = default_grant_ttl
        self._requests: dict[str, AccessRequest] = {}
        self._grants: dict[str, AccessGrant] = {}

    # -- decisions -----------------------------------------------------------

    def decide(
        self,
        participant: Participant,
        dataset_id: str,
        action: Action | str,
        purpose: str | None = None,
        now: datetime | None = None,
    ) -> Decision:
        action = Action(action)
        dataset = self.catalog.get(dataset_id)
        if not participant.has_role(Role.CONSUMER):
            return Decision(allowed=False, reason="participant does not hold the consumer role")
        policy = self.policies.get(dataset.policy_id) if dataset.policy_id else None
        ctx = EvaluationContext(
            participant=participant,
            action=action,
            purpose=purpose,
            timestamp=now or datetime.now(timezone.utc),
            usage_count=self.usage_count(participant.id, dataset_id),
        )
        return self.evaluator.evaluate(policy, ctx)

    def request_access(
        self,
        participant: Participant,
        dataset_id: str,
        action: Action | str,
        purpose: str | None = None,
        max_uses: int | None = None,
        ttl: timedelta | None = None,
    ) -> AccessRequest:
        action = Action(action)
        request = AccessRequest(
            requester_id=participant.id, dataset_id=dataset_id, action=action, purpose=purpose
        )
        self._requests[request.id] = request
        decision = self.decide(participant, dataset_id, action, purpose)
        request.reason = decision.reason

        if not decision.allowed:
            request.status = RequestStatus.DENIED
            self.audit.log(
                participant.id, "access.requested", dataset_id, Outcome.DENIED,
                request_id=request.id, action=action.value, purpose=purpose, reason=decision.reason,
            )
            return request

        dataset = self.catalog.get(dataset_id)
        policy = self.policies.get(dataset.policy_id)  # type: ignore[arg-type]
        ttl = ttl or self.default_grant_ttl
        grant = AccessGrant(
            request_id=request.id,
            dataset_id=dataset_id,
            provider_id=dataset.owner_id,
            consumer_id=participant.id,
            action=action,
            purpose=purpose,
            policy_id=policy.id,
            policy_version=policy.version,
            obligations=decision.obligations,
            expires_at=datetime.now(timezone.utc) + ttl if ttl else None,
            max_uses=max_uses,
        )
        self._grants[grant.id] = grant
        request.status = RequestStatus.GRANTED
        request.grant_id = grant.id
        self.audit.log(
            participant.id, "access.requested", dataset_id, Outcome.SUCCESS,
            request_id=request.id, grant_id=grant.id, action=action.value, purpose=purpose,
            rule_id=decision.rule_id, obligations=[d.action for d in decision.obligations],
        )
        return request

    # -- grants --------------------------------------------------------------

    def get_grant(self, grant_id: str) -> AccessGrant:
        try:
            grant = self._grants[grant_id]
        except KeyError:
            raise NotFoundError(f"grant '{grant_id}' not found") from None
        grant.refresh_status()
        return grant

    def get_request(self, request_id: str) -> AccessRequest:
        try:
            return self._requests[request_id]
        except KeyError:
            raise NotFoundError(f"request '{request_id}' not found") from None

    def grants_for(self, participant_id: str) -> list[AccessGrant]:
        grants = [
            g for g in self._grants.values()
            if participant_id in (g.consumer_id, g.provider_id)
        ]
        for g in grants:
            g.refresh_status()
        return grants

    def usage_count(self, consumer_id: str, dataset_id: str) -> int:
        return sum(
            g.uses for g in self._grants.values()
            if g.consumer_id == consumer_id and g.dataset_id == dataset_id
        )

    def use_grant(self, grant_id: str, participant: Participant) -> AccessGrant:
        """Enforce the grant for one use; raises if access is no longer allowed."""
        grant = self.get_grant(grant_id)
        if grant.consumer_id != participant.id:
            self.audit.log(participant.id, "grant.used", grant.dataset_id, Outcome.DENIED,
                           grant_id=grant_id, reason="not the grant holder")
            raise AuthorizationError("grant belongs to another participant")
        if grant.status != GrantStatus.ACTIVE:
            self.audit.log(participant.id, "grant.used", grant.dataset_id, Outcome.DENIED,
                           grant_id=grant_id, reason=f"grant {grant.status.value}")
            raise AuthorizationError(f"grant is {grant.status.value}")

        try:
            decision = self.decide(participant, grant.dataset_id, grant.action, grant.purpose)
        except NotFoundError:
            decision = Decision(allowed=False, reason="dataset withdrawn")
        if not decision.allowed:
            grant.status = GrantStatus.REVOKED
            self.audit.log(participant.id, "grant.used", grant.dataset_id, Outcome.DENIED,
                           grant_id=grant_id, reason=decision.reason)
            raise PolicyViolationError(decision.reason)

        grant.uses += 1
        grant.refresh_status()
        self.audit.log(participant.id, "grant.used", grant.dataset_id, Outcome.SUCCESS,
                       grant_id=grant_id, uses=grant.uses)
        return grant

    def revoke_grant(self, grant_id: str, requester_id: str) -> AccessGrant:
        grant = self.get_grant(grant_id)
        if requester_id not in (grant.provider_id, grant.consumer_id):
            raise AuthorizationError("only the provider or consumer can revoke a grant")
        grant.status = GrantStatus.REVOKED
        self.audit.log(requester_id, "grant.revoked", grant.dataset_id, grant_id=grant_id)
        return grant
