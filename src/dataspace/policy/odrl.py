"""Serialisation of policies as ODRL 2.2 JSON-LD offers (and back).

This is the representation published in the catalog, so that policies can
be read by any ODRL-aware system.
"""

from __future__ import annotations

from typing import Any

from dataspace.policy.model import Action, Constraint, Duty, Operator, Policy, Rule, RuleType

ODRL_CONTEXT = "http://www.w3.org/ns/odrl.jsonld"


def _rule_to_odrl(rule: Rule, policy: Policy) -> list[dict[str, Any]]:
    out = []
    for action in rule.actions:
        entry: dict[str, Any] = {"uid": rule.id, "action": action.value, "target": policy.target}
        if rule.assignees:
            entry["assignee"] = rule.assignees
        if rule.constraints:
            entry["constraint"] = [
                {"leftOperand": c.left_operand, "operator": c.operator.value, "rightOperand": c.right_operand}
                for c in rule.constraints
            ]
        if rule.duties:
            entry["duty"] = [{"action": d.action, **({"refinement": d.parameters} if d.parameters else {})}
                             for d in rule.duties]
        out.append(entry)
    return out


def to_odrl(policy: Policy) -> dict[str, Any]:
    document: dict[str, Any] = {
        "@context": ODRL_CONTEXT,
        "@type": "Offer",
        "uid": policy.uid,
        "assigner": policy.assigner,
        "target": policy.target,
        "version": policy.version,
    }
    for kind in RuleType:
        rules = [r for r in policy.rules if r.type == kind]
        if rules:
            document[kind.value] = [e for r in rules for e in _rule_to_odrl(r, policy)]
    return document


def from_odrl(document: dict[str, Any]) -> Policy:
    rules: dict[str, Rule] = {}
    for kind in RuleType:
        for entry in document.get(kind.value, []):
            uid = entry["uid"]
            if uid in rules:  # one ODRL entry per action -> merge back into one rule
                rules[uid].actions.append(Action(entry["action"]))
                continue
            rules[uid] = Rule(
                id=uid,
                type=kind,
                actions=[Action(entry["action"])],
                assignees=entry.get("assignee"),
                constraints=[
                    Constraint(left_operand=c["leftOperand"], operator=Operator(c["operator"]),
                               right_operand=c["rightOperand"])
                    for c in entry.get("constraint", [])
                ],
                duties=[Duty(action=d["action"], parameters=d.get("refinement", {}))
                        for d in entry.get("duty", [])],
            )
    return Policy(
        uid=document["uid"], assigner=document["assigner"], target=document["target"],
        version=document.get("version", 1), rules=list(rules.values()),
    )
