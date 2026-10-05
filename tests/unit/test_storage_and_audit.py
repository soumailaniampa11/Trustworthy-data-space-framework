import pytest

from dataspace.audit.chain import AuditTrail, verify_chain
from dataspace.common.blobs import FileBlobStore, storage_from_url
from dataspace.common.errors import IntegrityViolation, NotFound
from dataspace.common.store import DocumentStore
from dataspace.identity.did import did_web, did_web_to_url


def test_document_store_upsert_and_order(tmp_path):
    store = DocumentStore(f"sqlite:///{tmp_path}/db.sqlite")
    trail = AuditTrail(store)
    for i in range(3):
        trail.record("did:web:a", "event", f"r{i}")
    first = store.find("audit", type(trail.events()[0]))[0]
    store.put("audit", "0", first)  # update keeps position
    assert [e.subject for e in trail.events()] == ["r0", "r1", "r2"]
    with pytest.raises(NotFound):
        store.get("audit", "99", type(first))


def test_audit_chain_detects_modification_deletion_reordering():
    trail = AuditTrail(DocumentStore())
    for i in range(4):
        trail.record("did:web:a", "event", f"r{i}")
    assert trail.verify() == 4

    events = trail.events()
    events[1].details["forged"] = True
    with pytest.raises(IntegrityViolation, match="event 1 was modified"):
        verify_chain(events)
    with pytest.raises(IntegrityViolation, match="sequence gap"):
        verify_chain(trail.events()[:1] + trail.events()[2:])
    swapped = trail.events()
    swapped[1], swapped[2] = swapped[2], swapped[1]
    with pytest.raises(IntegrityViolation):
        verify_chain(swapped)


def test_blob_stores(tmp_path):
    memory = storage_from_url("memory://")
    memory.put("a/b", b"x")
    assert memory.get("a/b") == b"x"
    files = storage_from_url(f"file://{tmp_path}/blobs")
    files.put("datasets/d", b"y")
    assert files.get("datasets/d") == b"y"
    with pytest.raises(NotFound):
        files.get("missing")
    with pytest.raises(ValueError):
        FileBlobStore(tmp_path / "blobs").put("../escape", b"z")


def test_did_web_mapping():
    did = did_web("http://connector-a:8000")
    assert did == "did:web:connector-a%3A8000"
    assert did_web_to_url(did, "http") == "http://connector-a:8000"
    assert did_web_to_url("did:web:example.org:org:unit") == "https://example.org/org/unit"
