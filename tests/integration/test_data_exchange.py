import pytest

from dataspace.catalog import sha256
from dataspace.core.exceptions import AuthorizationError, TransferError
from dataspace.exchange import TransferState


def test_end_to_end_exchange(space):
    request = space.request_access("lab", "records", "read", "research")
    process, data = space.transfer(request.grant_id, "lab")
    assert data == b"id,value\n1,42\n"
    assert process.state == TransferState.COMPLETED
    assert process.checksum == sha256(data)
    assert space.audit.query(event_type="transfer.completed", actor="lab")
    assert space.audit.verify()


def test_tampered_provider_data_is_detected(space):
    grant_id = space.request_access("lab", "records", "read", "research").grant_id
    space.connectors["hospital"]._storage["records"] = b"forged"
    with pytest.raises(TransferError, match="checksum mismatch"):
        space.transfer(grant_id, "lab")


def test_impersonated_provider_signature_is_detected(space):
    grant_id = space.request_access("lab", "records", "read", "research").grant_id
    space.registry.get("hospital").connector_key = space.connectors["corp"].public_key
    with pytest.raises(TransferError, match="invalid provider signature"):
        space.transfer(grant_id, "lab")


def test_withdrawn_dataset_stops_transfers(space):
    grant_id = space.request_access("lab", "records", "read", "research").grant_id
    space.withdraw_dataset("hospital", "records")
    with pytest.raises(AuthorizationError):
        space.transfer(grant_id, "lab")
