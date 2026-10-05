import base64

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from dataspace import DataSpace
from dataspace.access import RequestStatus
from dataspace.core.config import load_participant_configs
from dataspace.identity import KeyPair
from tests.conftest import PARTICIPANTS_DIR


@pytest.fixture
def configured():
    return DataSpace.from_configs(load_participant_configs(PARTICIPANTS_DIR))


def test_configs_are_loaded(configured):
    space, keys = configured
    assert {p.id for p in space.registry.list()} == {"participant_a", "participant_b", "participant_c"}
    assert {d.id for d in space.catalog.search()} == {"clinical-records-2024", "urban-mobility-2024"}
    assert space.catalog.get("clinical-records-2024").size > 0


def test_cross_participant_policies(configured):
    space, _ = configured
    # EU research institute may analyse clinical data for research...
    granted = space.request_access("participant_b", "clinical-records-2024", "analyze", "research")
    assert granted.status == RequestStatus.GRANTED
    _, data = space.transfer(granted.grant_id, "participant_b")
    assert data.startswith(b"patient_pseudo_id")
    # ...but not download it, and a non-EU company cannot access it at all.
    assert space.request_access("participant_b", "clinical-records-2024", "download", "research").status == RequestStatus.DENIED
    assert space.request_access("participant_c", "clinical-records-2024", "read", "research").status == RequestStatus.DENIED
    # Open mobility data is available to everyone.
    assert space.request_access("participant_c", "urban-mobility-2024", "download").status == RequestStatus.GRANTED


def test_usage_count_limit(configured):
    space, _ = configured
    for _ in range(10):
        grant_id = space.request_access("participant_b", "clinical-records-2024", "read", "research").grant_id
        space.transfer(grant_id, "participant_b")
    denied = space.request_access("participant_b", "clinical-records-2024", "read", "research")
    assert denied.status == RequestStatus.DENIED and "usage_count" in denied.reason


def login(client: TestClient, pid: str, keys: KeyPair) -> dict:
    challenge = client.post("/auth/challenge", json={"participant_id": pid}).json()["challenge"]
    token = client.post(
        "/auth/token", json={"participant_id": pid, "signature": keys.sign(challenge.encode())}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_full_flow_over_http():
    client = TestClient(create_app())
    provider_keys, consumer_keys = KeyPair(), KeyPair()
    for pid, keys, roles, country in [
        ("prov", provider_keys, ["provider"], "FR"),
        ("cons", consumer_keys, ["consumer"], "DE"),
    ]:
        r = client.post("/participants", json={
            "id": pid, "name": pid, "organization": pid, "public_key": keys.public_key,
            "roles": roles, "attributes": {"country": country},
        })
        assert r.status_code == 201

    assert client.get("/participants/me").status_code == 401
    prov, cons = login(client, "prov", provider_keys), login(client, "cons", consumer_keys)
    assert client.get("/participants/me", headers=cons).json()["id"] == "cons"

    r = client.post("/datasets", headers=prov, json={
        "id": "ds", "metadata": {"title": "Energy load"},
        "content_base64": base64.b64encode(b"kwh\n12\n").decode(),
        "rules": [{"actions": ["read"], "constraints": [
            {"left_operand": "participant.country", "operator": "eq", "right_operand": "DE"}]}],
    })
    assert r.status_code == 201
    assert client.get("/datasets", params={"q": "energy"}).json()[0]["id"] == "ds"
    assert client.get("/datasets/ds/policy").json()["version"] == 1

    # Consumer cannot publish (no provider role) nor change someone else's policy.
    assert client.put("/datasets/ds/policy", headers=cons, json={"rules": []}).status_code == 403

    req = client.post("/access/requests", headers=cons, json={"dataset_id": "ds", "action": "read"}).json()
    assert req["status"] == "granted"
    r = client.post(f"/access/grants/{req['grant_id']}/transfer", headers=cons)
    assert base64.b64decode(r.json()["content_base64"]) == b"kwh\n12\n"

    # Provider revokes; further transfers are refused.
    assert client.post(f"/access/grants/{req['grant_id']}/revoke", headers=prov).json()["status"] == "revoked"
    assert client.post(f"/access/grants/{req['grant_id']}/transfer", headers=cons).status_code == 403

    events = client.get("/audit", headers=prov).json()
    assert any(e["event_type"] == "transfer.completed" for e in events)
    assert client.get("/audit/verify").json()["valid"] is True
