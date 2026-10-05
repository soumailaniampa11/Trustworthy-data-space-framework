from datetime import datetime, timezone

import pytest

from dataspace.policy import (
    Action, Constraint, Duty, EvaluationContext, Policy, PolicyEvaluator, Rule, RuleType,
    from_odrl, satisfied, to_odrl,
)
from tests.conftest import subject

pdp = PolicyEvaluator()


def ctx(action=Action.READ, purpose="research", did="did:web:p", **claims):
    return EvaluationContext(subject=subject(did, **claims), action=action, purpose=purpose)


def policy(*rules):
    return Policy(uid="urn:policy:ds:v1", assigner="did:web:owner", target="ds", rules=list(rules))


def c(left, op, right):
    return Constraint(left_operand=left, operator=op, right_operand=right)


def test_deny_by_default():
    assert not pdp.evaluate(None, ctx()).permitted
    assert not pdp.evaluate(policy(), ctx()).permitted


def test_permission_returns_obligations():
    rule = Rule(actions=[Action.READ], constraints=[c("participant.country", "eq", "FR")],
                duties=[Duty(action="delete", parameters={"after_days": 30})])
    decision = pdp.evaluate(policy(rule), ctx(country="FR"))
    assert decision.permitted and decision.rule_id == rule.id
    assert decision.obligations[0].parameters == {"after_days": 30}


def test_unmet_constraints_are_explained():
    rule = Rule(id="r1", actions=[Action.READ], constraints=[c("participant.country", "eq", "FR")])
    decision = pdp.evaluate(policy(rule), ctx(country="US"))
    assert not decision.permitted
    assert decision.reason == "constraints not satisfied: r1: participant.country eq 'FR'"


def test_unproven_claim_never_satisfies_even_negative_constraints():
    rule = Rule(actions=[Action.READ], constraints=[c("participant.country", "neq", "US")])
    assert not pdp.evaluate(policy(rule), ctx()).permitted


def test_prohibition_overrides_permission():
    allow = Rule(actions=[Action.READ, Action.DISTRIBUTE])
    deny = Rule(type=RuleType.PROHIBITION, actions=[Action.DISTRIBUTE])
    assert pdp.evaluate(policy(allow, deny), ctx(action=Action.READ)).permitted
    decision = pdp.evaluate(policy(allow, deny), ctx(action=Action.DISTRIBUTE))
    assert not decision.permitted and decision.rule_id == deny.id


def test_assignees():
    rule = Rule(actions=[Action.READ], assignees=["did:web:alice"])
    assert pdp.evaluate(policy(rule), ctx(did="did:web:alice")).permitted
    assert not pdp.evaluate(policy(rule), ctx(did="did:web:bob")).permitted


@pytest.mark.parametrize("operator, left, right, expected", [
    ("eq", "a", "a", True), ("neq", "a", "a", False),
    ("lt", 5, 6, True), ("lteq", 5, 5, True), ("gt", 5, 5, False), ("gteq", 5, 5, True),
    ("isAnyOf", "a", ["a", "b"], True), ("isNoneOf", "a", ["a"], False),
    ("hasPart", ["iso27001", "hds"], "hds", True), ("hasPart", ["iso27001"], ["iso27001", "hds"], False),
    ("lt", 5, "ten", False),
])
def test_operators(operator, left, right, expected):
    context = ctx()
    context.extra["x"] = left
    assert satisfied(c("x", operator, right), context) is expected


def test_datetime_constraints():
    context = ctx()
    context.timestamp = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert satisfied(c("datetime", "lt", "2027-01-01T00:00:00"), context)
    assert not satisfied(c("datetime", "gteq", "2027-01-01T00:00:00+00:00"), context)


def test_odrl_roundtrip():
    original = policy(
        Rule(id="p", actions=[Action.READ, Action.AGGREGATE],
             constraints=[c("purpose", "isAnyOf", ["research"])], duties=[Duty(action="attribute")]),
        Rule(id="q", type=RuleType.PROHIBITION, actions=[Action.DISTRIBUTE], assignees=["did:web:x"]),
    )
    document = to_odrl(original)
    assert document["@type"] == "Offer"
    assert {p["action"] for p in document["permission"]} == {"read", "aggregate"}
    assert document["permission"][0]["constraint"][0]["operator"] == "isAnyOf"
    assert from_odrl(document) == original
