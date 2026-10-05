"""Narrated demo of every trust mechanism of the data space.

Builds the data space from the participant configs, then walks through:
identity, catalog, policy decisions, continuous usage control, usage limits,
attack detection and the audit trail.

Usage: python scripts/seed_data.py [participants_dir]
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from dataspace import DataSpace  # noqa: E402
from dataspace.audit import Outcome, verify_chain  # noqa: E402
from dataspace.core.config import load_participant_configs  # noqa: E402
from dataspace.core.exceptions import DataSpaceError  # noqa: E402
from dataspace.identity import KeyPair  # noqa: E402
from dataspace.policy import Constraint, Rule  # noqa: E402

_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _style(code: str):
    return lambda text: f"\033[{code}m{text}\033[0m" if _COLOR else str(text)


bold, dim, green, red, cyan, yellow = (_style(c) for c in ("1", "2", "32", "31", "36", "33"))
OK, KO = green("✔"), red("✘")


def section(number: int, title: str, explanation: str) -> None:
    print(f"\n{bold(cyan(f'━━ {number}. {title} '))}{cyan('━' * max(0, 60 - len(title)))}")
    print(dim(f"   {explanation}"))


def outcome(allowed: bool, label: str, reason: str = "") -> None:
    mark = OK if allowed else KO
    print(f"   {mark} {label}" + (f"\n      {dim('→ ' + reason)}" if reason else ""))


def expect_failure(label: str, action) -> None:
    """Run an action that must be refused; ✘ means the data space blocked it."""
    try:
        action()
        print(f"   {bold(red('⚠ NOT DETECTED'))} {label}")
    except DataSpaceError as exc:
        outcome(False, f"{label}  {red('BLOCKED')}", f"{type(exc).__name__}: {exc}")


def describe_rule(rule: Rule) -> str:
    actions = ",".join(a.value for a in rule.actions)
    cons = " AND ".join(f"{c.left_operand} {c.operator.value} {c.right_operand}" for c in rule.constraints)
    text = f"{rule.type.value.upper():<11} {actions}" + (f" IF {cons}" if cons else "")
    if rule.duties:
        text += f"  ⇒ duties: {', '.join(d.action for d in rule.duties)}"
    return text


def main(participants_dir: Path) -> None:
    space, keys = DataSpace.from_configs(load_participant_configs(participants_dir))
    A, B, C = "participant_a", "participant_b", "participant_c"
    clinical, mobility = "clinical-records-2024", "urban-mobility-2024"

    print(bold("\nTrustworthy Data Space — demo"))

    # 1 -----------------------------------------------------------------------
    section(1, "Identity", "Each participant proves who it is by signing a random challenge (Ed25519).")
    for p in space.registry.list():
        token = space.login(p.id, keys[p.id])
        roles = "/".join(sorted(r.value for r in p.roles))
        outcome(True, f"{bold(p.name):<40} {p.id}  [{roles}]  {dim(p.attributes)}",
                f"session token {token[:24]}…")
    attacker = KeyPair()
    challenge = space.identity.create_challenge(A)
    expect_failure("Impersonation of participant_a with a stolen id but the wrong key",
                   lambda: space.identity.authenticate(A, attacker.sign(challenge.encode())))
    payload, signature = space.login(B, keys[B]).split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload))
    claims["sub"] = A
    forged = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True).encode()).decode()
    expect_failure("participant_b edits its token to claim it is participant_a",
                   lambda: space.identity.verify_token(f"{forged}.{signature}"))

    # 2 -----------------------------------------------------------------------
    section(2, "Catalog & policies", "Only offers are published; the data stays in each provider's connector.")
    for d in space.catalog.search():
        print(f"   {bold(d.id)}  {dim(f'owner={d.owner_id} · {d.metadata.sensitivity.value} · {d.size} B · sha256={d.checksum[:12]}…')}")
        for rule in space.policies.get(d.policy_id).rules:
            print(f"      {yellow(rule.id):<28} {describe_rule(rule)}")

    # 3 -----------------------------------------------------------------------
    section(3, "Access decisions", "Deny by default; prohibitions override permissions; every decision is explained.")
    scenarios = [
        (B, clinical, "analyze", "research", "EU research institute analyses clinical data"),
        (B, clinical, "read", "marketing", "same institute, but for marketing"),
        (B, clinical, "download", "research", "same institute tries to download"),
        (C, clinical, "read", "research", "US company reads clinical data"),
        (C, mobility, "download", None, "US company downloads open mobility data"),
    ]
    grants = {}
    for consumer, dataset, action, purpose, label in scenarios:
        request = space.request_access(consumer, dataset, action, purpose)
        allowed = request.grant_id is not None
        outcome(allowed, f"{label}  {dim(f'({consumer} · {action} · purpose={purpose})')}", request.reason)
        if allowed:
            grant = space.authz.get_grant(request.grant_id)
            process, data = space.transfer(grant.id, consumer)
            grants[(consumer, dataset)] = grant.id
            duties = ", ".join(f"{d.action}{d.parameters or ''}" for d in grant.obligations) or "none"
            print(f"      {dim(f'transfer {process.id}: {len(data)} B, checksum and provider signature verified')}")
            print(f"      {dim(f'obligations accepted: {duties}')}")

    # 4 -----------------------------------------------------------------------
    section(4, "Continuous usage control",
            "The policy is re-checked at every use: changes apply to grants already issued.")
    grant_id = space.request_access(B, clinical, "read", "research").grant_id
    space.transfer(grant_id, B)
    outcome(True, "participant_b holds an active grant and uses it once")
    space.set_policy(A, clinical, [
        Rule(id="france-only", actions=["read", "analyze"], constraints=[
            Constraint(left_operand="participant.country", operator="eq", right_operand="FR"),
        ]),
    ])
    print(f"   {yellow('↻')} participant_a tightens its policy to {bold('France only')} (policy v2)")
    expect_failure("participant_b re-uses its old grant", lambda: space.transfer(grant_id, B))

    grant_id = grants[(C, mobility)]
    space.authz.revoke_grant(grant_id, B)
    print(f"   {yellow('↻')} participant_b revokes the mobility grant of participant_c")
    expect_failure("participant_c re-uses the revoked grant", lambda: space.transfer(grant_id, C))

    # 5 -----------------------------------------------------------------------
    section(5, "Usage limits", "A grant can be limited to a number of uses (here: 2).")
    grant_id = space.request_access(C, mobility, "read", max_uses=2).grant_id
    for i in (1, 2):
        space.transfer(grant_id, C)
        outcome(True, f"use {i}/2")
    expect_failure("use 3/2", lambda: space.transfer(grant_id, C))

    # 6 -----------------------------------------------------------------------
    section(6, "Attack detection", "Integrity of data and of the audit trail is verified cryptographically.")
    grant_id = space.request_access(C, mobility, "read").grant_id
    storage = space.connectors[B]._storage
    original = storage[mobility]
    storage[mobility] = original.replace(b"143", b"999")
    expect_failure("Provider data silently modified after publication",
                   lambda: space.transfer(grant_id, C))
    storage[mobility] = original

    tampered = copy.deepcopy(space.audit.events)
    victim = next(e for e in tampered if e.outcome == Outcome.DENIED)
    victim.outcome = Outcome.SUCCESS
    expect_failure(f"Audit record #{victim.sequence} rewritten from 'denied' to 'success'",
                   lambda: verify_chain(tampered))
    expect_failure("Audit record deleted", lambda: verify_chain(tampered[:3] + tampered[4:]))

    # 7 -----------------------------------------------------------------------
    section(7, "Audit trail", "Every action is recorded in a hash-chained, tamper-evident log.")
    events = space.audit.events
    for e in events[-12:]:
        color = {Outcome.SUCCESS: green, Outcome.DENIED: red, Outcome.FAILURE: yellow}[e.outcome]
        print(f"   {dim(f'#{e.sequence:<3}')} {e.actor:<14} {e.event_type:<20} {(e.resource or ''):<22} "
              f"{color(e.outcome.value):<8} {dim(e.hash[:10])}")
    if len(events) > 12:
        print(dim(f"   … {len(events) - 12} earlier events"))
    space.audit.verify()
    by_outcome = {o: len(space.audit.query(outcome=o)) for o in Outcome}
    print(f"\n   {OK} {bold(f'{len(events)} events')}, hash chain valid  "
          f"{dim(f'(success {by_outcome[Outcome.SUCCESS]} · denied {by_outcome[Outcome.DENIED]} · failure {by_outcome[Outcome.FAILURE]})')}\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "participants")
