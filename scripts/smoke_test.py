"""Check a running deployment (``docker compose up``) end to end.

Negotiates a contract between connectors A and B, transfers the data and
verifies both audit trails against the transparency log. Non-destructive:
it only adds a contract and a transfer.

Usage: python scripts/smoke_test.py [--a http://localhost:8001] [--b http://localhost:8002]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dataspace.client import ConnectorClient  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--a", default="http://localhost:8001")
    parser.add_argument("--b", default="http://localhost:8002")
    parser.add_argument("--a-key", default="participant_a-key")
    parser.add_argument("--b-key", default="participant_b-key")
    args = parser.parse_args()

    hospital, lab = ConnectorClient(args.a, args.a_key), ConnectorClient(args.b, args.b_key)
    hospital_did = hospital.did
    print(f"connector A  {hospital_did}  ({len(hospital.identity()['credentials'])} credentials)")
    print(f"connector B  {lab.did}  ({len(lab.identity()['credentials'])} credentials)")
    print(f"catalog      {[o.id for o in lab.catalog()]}")

    negotiation = lab.negotiate(hospital_did, "clinical-records-2024", "read", "research")
    print(f"negotiation  {negotiation.state.value}: {negotiation.reason}")
    if negotiation.agreement is None:
        sys.exit("expected an agreement")
    transfer = lab.transfer(negotiation.agreement.id)
    data = lab.data(transfer.id)
    print(f"transfer     {transfer.state.value}: {len(data)} bytes, sha256 {transfer.checksum[:16]}…")
    for name, client in (("A", hospital), ("B", lab)):
        report = client.verify_audit()
        print(f"audit {name}      {report['events']} events, {report['verified_inclusions']} inclusion proofs, "
              f"log size {report['tree_size']}")
    print("OK")


if __name__ == "__main__":
    main()
