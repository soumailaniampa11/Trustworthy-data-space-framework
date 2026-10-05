"""Policy decision point.

Semantics (deny-by-default, prohibition-overrides):

1. If any applicable prohibition matches, the request is denied.
2. Otherwise, if an applicable permission has all its constraints satisfied,
   the request is allowed and the permission's duties become obligations.
3. Otherwise the request is denied.

Every decision carries a human-readable reason so that it can be audited.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from dataspace.identity.participant import Participant
from dataspace.policy.policy import Action, Constraint, Duty, Operator, Policy, Rule, RuleType

_MISSING = object()


class EvaluationContext(BaseModel):
    participant: Participant
    action: Action
    purpose: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    usage_count: int = 0
    extra: dict[str, Any] = Field(default_factory=dict)

    def resolve(self, path: str) -> Any:
        head, _, rest = path.partition(".")
        if head == "participant":
            if rest in ("id", "name", "organization"):
                return getattr(self.participant, rest)
            if rest == "roles":
                return sorted(r.value for r in self.participant.roles)
            return self.participant.attributes.get(rest, _MISSING)
        if head == "datetime":
            return self.timestamp
        if head == "purpose":
            return self.purpose if self.purpose is not None else _MISSING
        if head == "usage_count":
            return self.usage_count
        return self.extra.get(path, _MISSING)


class Decision(BaseModel):
    allowed: bool
    reason: str
    rule_id: str | None = None
    obligations: list[Duty] = Field(default_factory=list)


def _coerce(left: Any, right: Any) -> Any:
    if isinstance(left, datetime) and isinstance(right, str):
        parsed = datetime.fromisoformat(right)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return right


def check_constraint(constraint: Constraint, ctx: EvaluationContext) -> bool:
    left = ctx.resolve(constraint.left_operand)
    if left is _MISSING:
        return False  # an absent claim never satisfies a constraint
    right = _coerce(left, constraint.right_operand)
    op = constraint.operator
    try:
        if op == Operator.EQ:
            return left == right
        if op == Operator.NEQ:
            return left != right
        if op == Operator.IN:
            return left in right
        if op == Operator.NOT_IN:
            return left not in right
        if op == Operator.LT:
            return left < right
        if op == Operator.LTE:
            return left <= right
        if op == Operator.GT:
            return left > right
        if op == Operator.GTE:
            return left >= right
    except TypeError:
        return False
    raise ValueError(f"unsupported operator {op}")


def _describe(c: Constraint) -> str:
    return f"{c.left_operand} {c.operator.value} {c.right_operand!r}"


class PolicyEvaluator:
    def _applies(self, rule: Rule, ctx: EvaluationContext) -> bool:
        if ctx.action not in rule.actions:
            return False
        return rule.assignees is None or ctx.participant.id in rule.assignees

    def evaluate(self, policy: Policy | None, ctx: EvaluationContext) -> Decision:
        if policy is None:
            return Decision(allowed=False, reason="no policy attached (deny by default)")

        candidates = [r for r in policy.rules if self._applies(r, ctx)]

        for rule in candidates:
            if rule.type == RuleType.PROHIBITION and all(
                check_constraint(c, ctx) for c in rule.constraints
            ):
                return Decision(
                    allowed=False,
                    reason=f"prohibited by rule {rule.id}",
                    rule_id=rule.id,
                )

        failures: list[str] = []
        for rule in candidates:
            if rule.type != RuleType.PERMISSION:
                continue
            failed = [c for c in rule.constraints if not check_constraint(c, ctx)]
            if not failed:
                return Decision(
                    allowed=True,
                    reason=f"permitted by rule {rule.id}",
                    rule_id=rule.id,
                    obligations=list(rule.duties),
                )
            failures.append(f"{rule.id}: " + ", ".join(_describe(c) for c in failed))

        if failures:
            return Decision(allowed=False, reason="constraints not satisfied: " + "; ".join(failures))
        return Decision(
            allowed=False,
            reason=f"no rule permits '{ctx.action.value}' for '{ctx.participant.id}'",
        )
