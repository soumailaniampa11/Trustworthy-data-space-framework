"""Register a participant on a running API and print its bearer token.

Generates a key pair locally, registers the participant, runs the
challenge-response login and prints the token to paste in Swagger
("Authorize" button at http://localhost:8000/docs).

Usage:
  python scripts/get_token.py <id> --roles provider consumer --attr country=FR
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dataspace.identity import KeyPair  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("id")
    parser.add_argument("--roles", nargs="+", default=["consumer"])
    parser.add_argument("--attr", nargs="*", default=[], help="key=value attributes")
    parser.add_argument("--url", default="http://localhost:8000")
    args = parser.parse_args()

    keys = KeyPair()
    attributes = dict(a.split("=", 1) for a in args.attr)
    with httpx.Client(base_url=args.url) as client:
        r = client.post("/participants", json={
            "id": args.id, "name": args.id, "organization": args.id,
            "public_key": keys.public_key, "roles": args.roles, "attributes": attributes,
        })
        r.raise_for_status()
        challenge = client.post("/auth/challenge", json={"participant_id": args.id}).json()["challenge"]
        r = client.post("/auth/token", json={
            "participant_id": args.id, "signature": keys.sign(challenge.encode()),
        })
        r.raise_for_status()
    print(r.json()["access_token"])


if __name__ == "__main__":
    main()
