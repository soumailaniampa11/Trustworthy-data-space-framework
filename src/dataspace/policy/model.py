"""Usage policies following the W3C ODRL 2.2 information model.

A policy governs one dataset (its *target*) and is issued by the data owner
(its *assigner*). It contains permissions and prohibitions over actions;
rules may be restricted to assignees, guarded by constraints, and
permissions may impose duties that the consumer accepts in the contract.
Action and operator names are those of the ODRL vocabulary.
"""

from __future__ import annotations

import secrets
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Action(str, Enum):
    USE = "use"
    READ = "read"
    AGGREGATE = "aggregate"
    DERIVE = "derive"
    MODIFY = "modify"
    REPRODUCE = "reproduce"
    """Make copies outside the agreed processing (e.g. bulk download)."""
    DISTRIBUTE = "distribute"
    """Share the data with third parties."""


class RuleType(str, Enum):
    PERMISSION = "permission"
    PROHIBITION = "prohibition"


class Operator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    LT = "lt"
    LTEQ = "lteq"
    GT = "gt"
    GTEQ = "gteq"
    IS_ANY_OF = "isAnyOf"
    IS_NONE_OF = "isNoneOf"
    HAS_PART = "hasPart"


class Constraint(BaseModel):
    """``leftOperand operator rightOperand``.

    ``left_operand`` is a path into the evaluation context:
    ``participant.<claim>`` (claims attested by verifiable credentials),
    ``participant.id``, ``purpose``, ``datetime`` or ``usage_count``.
    """

    left_operand: str
    operator: Operator
    right_operand: Any


class Duty(BaseModel):
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    id: str = Field(default_factory=lambda: f"rule-{secrets.token_hex(4)}")
    type: RuleType = RuleType.PERMISSION
    actions: list[Action]
    assignees: list[str] | None = None
    """DIDs the rule applies to; ``None`` means any participant."""
    constraints: list[Constraint] = Field(default_factory=list)
    duties: list[Duty] = Field(default_factory=list)


class Policy(BaseModel):
    uid: str
    assigner: str
    target: str
    version: int = 1
    rules: list[Rule] = Field(default_factory=list)
