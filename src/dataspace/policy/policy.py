"""Usage policies, inspired by the W3C ODRL information model.

A policy is a set of rules attached to a dataset. Each rule is either a
*permission* or a *prohibition* over an action, optionally restricted to some
assignees and guarded by constraints. Permissions may carry *duties*
(obligations the consumer accepts when using the data).
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from dataspace.core.exceptions import AlreadyExistsError, NotFoundError


class Action(str, Enum):
    READ = "read"
    DOWNLOAD = "download"
    AGGREGATE = "aggregate"
    ANALYZE = "analyze"
    SHARE = "share"
    MODIFY = "modify"


class RuleType(str, Enum):
    PERMISSION = "permission"
    PROHIBITION = "prohibition"


class Operator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    IN = "in"
    NOT_IN = "not_in"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"


class Constraint(BaseModel):
    """``left_operand <operator> right_operand``.

    ``left_operand`` is a dotted path into the evaluation context, e.g.
    ``participant.country``, ``purpose``, ``datetime`` or ``usage_count``.
    """

    left_operand: str
    operator: Operator
    right_operand: Any


class Duty(BaseModel):
    """An obligation attached to a permission (e.g. ``delete_after`` 30 days)."""

    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    id: str = Field(default_factory=lambda: f"rule-{uuid.uuid4().hex[:8]}")
    type: RuleType = RuleType.PERMISSION
    actions: list[Action]
    assignees: list[str] | None = None
    """Participant ids the rule applies to; ``None`` means everyone."""
    constraints: list[Constraint] = Field(default_factory=list)
    duties: list[Duty] = Field(default_factory=list)


class Policy(BaseModel):
    id: str = Field(default_factory=lambda: f"policy-{uuid.uuid4().hex[:8]}")
    assigner: str
    """Participant id of the data owner who issues the policy."""
    target: str
    """Dataset id the policy governs."""
    rules: list[Rule] = Field(default_factory=list)
    version: int = 1


class PolicyStore:
    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}

    def add(self, policy: Policy) -> Policy:
        if policy.id in self._policies:
            raise AlreadyExistsError(f"policy '{policy.id}' already exists")
        self._policies[policy.id] = policy
        return policy

    def get(self, policy_id: str) -> Policy:
        try:
            return self._policies[policy_id]
        except KeyError:
            raise NotFoundError(f"policy '{policy_id}' not found") from None

    def for_target(self, dataset_id: str) -> list[Policy]:
        return [p for p in self._policies.values() if p.target == dataset_id]
