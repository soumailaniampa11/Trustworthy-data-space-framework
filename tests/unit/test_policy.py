from datetime import datetime, timezone

import pytest

from dataspace.policy import (
    Action,
    Constraint,
    Duty,
    EvaluationContext,
    Policy,
    PolicyEvaluator,
    Rule,
    RuleType,
    check_constraint,
)
from tests.conftest import make_participant

evaluator = PolicyEvaluator()


def ctx(action=Action.READ, purpose="research", pid="p1", **attrs):
    return EvaluationContext(participant=make_participant(pid, **attrs), action=action, purpose=purpose)


def policy(*rules):
    return Policy(assigner="owner", target="ds", rules=list(rules))


def test_deny_by_default():
    assert not evaluator.evaluate(None, ctx()).allowed
    assert not evaluator.evaluate(policy(), ctx()).allowed


def test_permission_with_satisfied_constraints_returns_duties():
    rule = Rule(
        actions=[Action.READ],
        constraints=[Constraint(left_operand="participant.country", operator="eq", right_operand="FR")],
        duties=[Duty(action="delete_after", parameters={"days": 30})],
    )
    decision = evaluator.evaluate(policy(rule), ctx(country="FR"))
    assert decision.allowed
    assert decision.rule_id == rule.id
    assert decision.obligations[0].action == "delete_after"


def test_unsatisfied_constraint_is_explained():
    rule = Rule(
        id="r1",
        actions=[Action.READ],
        constraints=[Constraint(left_operand="participant.country", operator="eq", right_operand="FR")],
    )
    decision = evaluator.evaluate(policy(rule), ctx(country="US"))
    assert not decision.allowed
    assert "participant.country eq 'FR'" in decision.reason


def test_missing_attribute_never_satisfies():
    rule = Rule(
        actions=[Action.READ],
        constraints=[Constraint(left_operand="participant.country", operator="neq", right_operand="US")],
    )
    assert not evaluator.evaluate(policy(rule), ctx()).allowed


def test_action_not_covered_is_denied():
    decision = evaluator.evaluate(policy(Rule(actions=[Action.READ])), ctx(action=Action.DOWNLOAD))
    assert not decision.allowed
    assert "no rule permits 'download'" in decision.reason


def test_prohibition_overrides_permission():
    allow = Rule(actions=[Action.READ, Action.SHARE])
    deny = Rule(type=RuleType.PROHIBITION, actions=[Action.SHARE])
    assert evaluator.evaluate(policy(allow, deny), ctx(action=Action.READ)).allowed
    decision = evaluator.evaluate(policy(allow, deny), ctx(action=Action.SHARE))
    assert not decision.allowed and decision.rule_id == deny.id


def test_assignees_restrict_rule():
    rule = Rule(actions=[Action.READ], assignees=["alice"])
    assert evaluator.evaluate(policy(rule), ctx(pid="alice")).allowed
    assert not evaluator.evaluate(policy(rule), ctx(pid="bob")).allowed


def test_datetime_constraint_parses_iso_strings():
    c = Constraint(left_operand="datetime", operator="lt", right_operand="2030-01-01T00:00:00")
    c_past = Constraint(left_operand="datetime", operator="lt", right_operand="2000-01-01T00:00:00+00:00")
    context = ctx()
    context.timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert check_constraint(c, context)
    assert not check_constraint(c_past, context)


@pytest.mark.parametrize(
    "operator, right, expected",
    [("in", ["a", "b"], True), ("not_in", ["a"], False), ("gte", 5, True), ("gt", 5, False),
     ("lte", 5, True), ("lt", 5, False), ("neq", 5, False)],
)
def test_operators(operator, right, expected):
    context = ctx()
    context.usage_count = 5
    context.extra["tier"] = "a"
    left = "tier" if operator in ("in", "not_in") else "usage_count"
    assert check_constraint(Constraint(left_operand=left, operator=operator, right_operand=right), context) is expected


def test_type_mismatch_is_false_not_error():
    c = Constraint(left_operand="usage_count", operator="lt", right_operand="ten")
    assert check_constraint(c, ctx()) is False
