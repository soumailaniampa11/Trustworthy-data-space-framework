"""Policy decision point (PDP).

Semantics: *deny by default* and *prohibition overrides permission*.

1. If an applicable prohibition has all its constraints satisfied -> deny.
2. Else, if an applicable permission has all its constraints satisfied ->
   permit, and its duties become obligations of the contract.
3. Else -> deny.

A rule is applicable when it covers the requested action and the requester
is among its assignees (if any). Constraints referring to a claim the
requester cannot prove are never satisfied. Every decision is explained.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from dataspace.common.clock import utcnow
from dataspace.identity.credentials import VerifiedSubject
from dataspace.policy.model import Action, Constraint, Duty, Operator, Policy, Rule, RuleType

_MISSING = object()


class EvaluationContext(BaseModel):
    subject: VerifiedSubject
    action: Action
    purpose: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    usage_count: int = 0
    extra: dict[str, Any] = Field(default_factory=dict)

    def resolve(self, path: str) -> Any:
        head, _, rest = path.partition(".")
        if head == "participant":
            if rest == "id":
                return self.subject.did
            return self.subject.claims.get(rest, _MISSING)
        if head == "purpose":
            return self.purpose if self.purpose is not None else _MISSING
        if head == "datetime":
            return self.timestamp
        if head == "usage_count":
            return self.usage_count
        return self.extra.get(path, _MISSING)


class Decision(BaseModel):
    permitted: bool
    reason: str
    rule_id: str | None = None
    obligations: list[Duty] = Field(default_factory=list)


def _coerce(left: Any, right: Any) -> Any:
    if isinstance(left, datetime) and isinstance(right, str):
        parsed = datetime.fromisoformat(right)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return right


def satisfied(constraint: Constraint, ctx: EvaluationContext) -> bool:
    left = ctx.resolve(constraint.left_operand)
    if left is _MISSING:
        return False
    right = _coerce(left, constraint.right_operand)
    try:
        match constraint.operator:
            case Operator.EQ:
                return left == right
            case Operator.NEQ:
                return left != right
            case Operator.LT:
                return left < right
            case Operator.LTEQ:
                return left <= right
            case Operator.GT:
                return left > right
            case Operator.GTEQ:
                return left >= right
            case Operator.IS_ANY_OF:
                return left in right
            case Operator.IS_NONE_OF:
                return left not in right
            case Operator.HAS_PART:
                wanted = right if isinstance(right, list) else [right]
                return isinstance(left, list) and all(w in left for w in wanted)
    except TypeError:
        return False
    return False


def describe(constraint: Constraint) -> str:
    return f"{constraint.left_operand} {constraint.operator.value} {constraint.right_operand!r}"


class PolicyEvaluator:
    def evaluate(self, policy: Policy | None, ctx: EvaluationContext) -> Decision:
        if policy is None:
            return Decision(permitted=False, reason="no policy attached (deny by default)")

        applicable = [r for r in policy.rules if self._applies(r, ctx)]
        for rule in applicable:
            if rule.type == RuleType.PROHIBITION and all(satisfied(c, ctx) for c in rule.constraints):
                return Decision(permitted=False, reason=f"prohibited by rule {rule.id}", rule_id=rule.id)

        failures = []
        for rule in applicable:
            if rule.type != RuleType.PERMISSION:
                continue
            unmet = [c for c in rule.constraints if not satisfied(c, ctx)]
            if not unmet:
                return Decision(permitted=True, reason=f"permitted by rule {rule.id}",
                                rule_id=rule.id, obligations=list(rule.duties))
            failures.append(f"{rule.id}: " + ", ".join(describe(c) for c in unmet))

        if failures:
            return Decision(permitted=False, reason="constraints not satisfied: " + "; ".join(failures))
        return Decision(permitted=False,
                        reason=f"no rule permits '{ctx.action.value}' for {ctx.subject.did}")

    @staticmethod
    def _applies(rule: Rule, ctx: EvaluationContext) -> bool:
        if ctx.action not in rule.actions:
            return False
        return rule.assignees is None or ctx.subject.did in rule.assignees
