"""Narrated demonstration of the trust mechanisms of the data space.

Runs the complete data space in-process (authority, catalog, transparency
log, three connectors) and walks through onboarding, publication,
negotiation, transfer, continuous usage control, revocation, attacks and
accountability.

Usage: python scripts/demo.py
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dataspace.common.errors import DataSpaceError  # noqa: E402
from dataspace.identity.credentials import issue_credential  # noqa: E402
from dataspace.policy import Constraint, Rule, from_odrl  # noqa: E402
from dataspace.protocol.negotiation import ContractRequest, NegotiationState  # noqa: E402
from dataspace.sim import LocalDataSpace  # noqa: E402

_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _style(code: str):
    return lambda text: f"\033[{code}m{text}\033[0m" if _COLOR else str(text)


bold, dim, green, red, cyan, yellow = (_style(c) for c in ("1", "2", "32", "31", "36", "33"))
CLINICAL, MOBILITY = "clinical-records-2024", "urban-mobility-2024"


def section(number: int, title: str, explanation: str) -> None:
    print(f"\n{bold(cyan(f'━━ {number}. {title} '))}{cyan('━' * max(0, 62 - len(title)))}")
    print(dim(f"   {explanation}"))


def ok(label: str, detail: str = "") -> None:
    print(f"   {green('✔')} {label}" + (f"\n      {dim('→ ' + detail)}" if detail else ""))


def refused(label: str, detail: str = "") -> None:
    print(f"   {red('✘')} {label}" + (f"\n      {dim('→ ' + detail)}" if detail else ""))


def info(label: str) -> None:
    print(f"   {yellow('↻')} {label}")


def must_fail(label: str, action) -> None:
    try:
        action()
    except DataSpaceError as exc:
        refused(f"{label}  {red('BLOCKED')}", f"{type(exc).__name__}: {exc.detail}")
        return
    print(f"   {bold(red('⚠ NOT DETECTED'))} {label}")


def short(did: str) -> str:
    return did.replace("did:web:", "").replace("%3A8000", "")


def main() -> None:
    space = LocalDataSpace().start()
    A, B, C = (space.clients[p] for p in ("participant_a", "participant_b", "participant_c"))
    a_did, b_did, c_did = (space.did(p) for p in ("participant_a", "participant_b", "participant_c"))
    cp_a, cp_b, cp_c = (space.control_planes[p] for p in ("participant_a", "participant_b", "participant_c"))

    print(bold("\nTrustworthy Data Space — demonstration"))
    print(dim(f"   authority {space.authority_did} · catalog · transparency log · 3 connectors"))

    # 1 ---------------------------------------------------------------------------------
    section(1, "Verifiable identity", "Facts about participants are attested by the authority, not self-declared.")
    for client, name in ((A, "Hospital A"), (B, "Research institute B"), (C, "Analytics company C")):
        identity = client.identity()
        claims = {}
        for vc in identity["credentials"]:
            claims.update({k: v for k, v in vc["credentialSubject"].items() if k not in ("id", "organization", "member")})
        types = ", ".join(t.replace("Credential", "") for vc in identity["credentials"] for t in vc["type"][1:])
        ok(f"{bold(name):<32} {identity['did']}", f"credentials: {types} · claims: {claims}")

    fake = issue_credential(c_did, cp_c.ctx.wallet.sign, c_did, ["JurisdictionCredential"],
                            {"region": "EU", "certifications": ["iso27001"]}, timedelta(days=1))
    forged_request = ContractRequest(
        negotiation_id="neg-forged", consumer=c_did, dataset_id=CLINICAL, policy_uid=f"urn:policy:{CLINICAL}:v1",
        action="read", purpose="research",
        presentation=cp_c.ctx.wallet.present(a_did, credentials=[fake]))
    must_fail("C presents a self-issued credential claiming to be an EU, ISO 27001 company",
              lambda: cp_a.handle_contract_request(forged_request))

    # 2 ---------------------------------------------------------------------------------
    section(2, "Federated catalog", "Providers publish signed DCAT offers with ODRL policies; data stays at the source.")
    for offer in B.catalog():
        policy = from_odrl(offer.policy)
        print(f"   {bold(offer.id)}  {dim(f'by {short(offer.provider)} · {offer.sensitivity} · {offer.byte_size} B · sha256 {offer.checksum[:12]}…')}")
        for rule in policy.rules:
            cons = " ∧ ".join(f"{c.left_operand} {c.operator.value} {c.right_operand}" for c in rule.constraints)
            duties = f"  ⇒ {', '.join(d.action for d in rule.duties)}" if rule.duties else ""
            actions = ",".join(a.value for a in rule.actions)
            print(f"      {yellow(rule.type.value.upper()):<22} {actions:<28} {dim(cons)}{dim(duties)}")

    # 3 ---------------------------------------------------------------------------------
    section(3, "Contract negotiation", "The provider verifies credentials, evaluates its policy, and both parties sign.")
    cases = [
        (B, a_did, CLINICAL, "read", "research", "B (EU, ISO 27001) reads clinical data for research"),
        (B, a_did, CLINICAL, "read", "marketing", "B reads clinical data for marketing"),
        (B, a_did, CLINICAL, "reproduce", "research", "B wants a copy of the clinical data"),
        (C, a_did, CLINICAL, "read", "research", "C (US, not certified) reads clinical data"),
        (C, b_did, MOBILITY, "reproduce", None, "C downloads open mobility data"),
    ]
    agreements = {}
    for client, provider, dataset, action, purpose, label in cases:
        negotiation = client.negotiate(provider, dataset, action, purpose)
        if negotiation.state == NegotiationState.FINALIZED:
            agreement = negotiation.agreement
            agreements[(client.base_url, dataset)] = agreement
            duties = ", ".join(f"{d.action}{d.parameters or ''}" for d in agreement.obligations)
            ok(label, f"{negotiation.reason} · agreement {agreement.id} signed by both parties · duties: {duties}")
        else:
            refused(label, negotiation.reason)

    # 4 ---------------------------------------------------------------------------------
    section(4, "Data transfer", "Single-use data address; the consumer verifies checksum and provider signature.")
    b_agreement = agreements[(B.base_url, CLINICAL)]
    transfer = B.transfer(b_agreement.id)
    ok(f"B receives {transfer.size} B of {CLINICAL}",
       f"sha256 {transfer.checksum[:16]}… matches the agreement · provider attestation verified")
    c_agreement = agreements[(C.base_url, MOBILITY)]
    transfer = C.transfer(c_agreement.id)
    ok(f"C receives {transfer.size} B of {MOBILITY}")

    # 5 ---------------------------------------------------------------------------------
    section(5, "Continuous usage control", "Every use is re-evaluated against the current policy and credentials.")
    A.set_policy(CLINICAL, [Rule(id="france-only", actions=["read"], constraints=[
        Constraint(left_operand="participant.country", operator="eq", right_operand="FR")])])
    info("A restricts its clinical data to French participants (policy v2)")
    must_fail("B uses its existing agreement again", lambda: B.transfer(b_agreement.id))
    B.revoke(c_agreement.id, "duty 'attribute' not fulfilled")
    info("B revokes C's agreement (duty not fulfilled)")
    must_fail("C uses the revoked agreement", lambda: C.transfer(c_agreement.id))
    space.revoke_credentials("participant_c")
    info("The authority revokes C's credentials")
    must_fail("C negotiates again for open data", lambda: C.negotiate(b_did, MOBILITY, "read"))

    # 6 ---------------------------------------------------------------------------------
    section(6, "Attacks", "Integrity, provenance and replay protection are enforced cryptographically.")
    replay = ContractRequest(negotiation_id="neg-replay", consumer=b_did, dataset_id=CLINICAL,
                             policy_uid=f"urn:policy:{CLINICAL}:v2", action="read", purpose="research",
                             presentation=cp_b.ctx.wallet.present(a_did))
    cp_a.handle_contract_request(replay)
    must_fail("An eavesdropper replays B's signed presentation to A",
              lambda: cp_a.handle_contract_request(replay))

    A.set_policy(CLINICAL, [Rule(id="eu-research", actions=["read"], constraints=[
        Constraint(left_operand="participant.region", operator="eq", right_operand="EU")])])
    agreement = B.negotiate(a_did, CLINICAL, "read", "research").agreement
    original = cp_a.blobs.get(f"datasets/{CLINICAL}")
    cp_a.blobs.put(f"datasets/{CLINICAL}", original.replace(b"J18.9", b"Z99.9"))
    must_fail("A's storage is altered after the agreement (one diagnosis changed)",
              lambda: B.transfer(agreement.id))
    cp_a.blobs.put(f"datasets/{CLINICAL}", original)

    events = cp_a.audit.events()
    victim = next(e for e in events if e.outcome.value == "denied")
    victim.outcome, victim.details["reason"] = victim.outcome.SUCCESS, "permitted"
    previous = "0" * 64
    for event in events:
        event.previous_hash, event.hash = previous, ""
        event.hash = event.compute_hash()
        previous = event.hash
        cp_a.ctx.store.put("audit", str(event.sequence), event)
    info(f"A's operator rewrites event #{victim.sequence} (denied → success) and recomputes its whole chain")
    must_fail("A's audit trail is verified against the transparency log", A.verify_audit)

    # 7 ---------------------------------------------------------------------------------
    section(7, "Accountability", "Each local event is anchored in an append-only Merkle log (RFC 9162).")
    for client, name in ((B, "B"), (C, "C")):
        report = client.verify_audit()
        ok(f"{name}: {report['events']} events, {report['verified_inclusions']} inclusion proofs verified",
           f"log size {report['tree_size']} · root {report['root_hash'][:16]}…")
    for event in B.audit()[-6:]:
        colour = {"success": green, "denied": red, "failure": yellow}[event.outcome.value]
        anchor = f"log #{event.anchor.index}" if event.anchor else "unanchored"
        print(f"   {dim(f'#{event.sequence:<3}')} {event.event_type:<30} {(event.subject or ''):<24} "
              f"{colour(f'{event.outcome.value:<8}')} {dim(anchor)}")
    print()


if __name__ == "__main__":
    main()
