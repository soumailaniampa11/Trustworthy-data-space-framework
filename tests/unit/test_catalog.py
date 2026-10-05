import pytest

from dataspace.catalog import Catalog, Dataset, DatasetMetadata, Sensitivity, sha256
from dataspace.core.exceptions import AlreadyExistsError, AuthorizationError, NotFoundError


def dataset(did="d1", owner="a", **meta):
    meta.setdefault("title", "Mobility counts")
    return Dataset(id=did, owner_id=owner, metadata=DatasetMetadata(**meta), checksum=sha256(b"x"), size=1)


def test_publish_get_and_duplicate():
    catalog = Catalog()
    catalog.publish(dataset())
    assert catalog.get("d1").owner_id == "a"
    with pytest.raises(AlreadyExistsError):
        catalog.publish(dataset())
    with pytest.raises(NotFoundError):
        catalog.get("missing")


def test_search_by_text_owner_and_sensitivity():
    catalog = Catalog()
    catalog.publish(dataset("d1", "a", keywords=["traffic"], sensitivity="public"))
    catalog.publish(dataset("d2", "b", title="Clinical records", sensitivity="confidential"))
    assert [d.id for d in catalog.search("TRAFFIC")] == ["d1"]
    assert [d.id for d in catalog.search("clinical")] == ["d2"]
    assert [d.id for d in catalog.search(owner_id="b")] == ["d2"]
    assert [d.id for d in catalog.search(sensitivity=Sensitivity.PUBLIC)] == ["d1"]


def test_only_owner_can_withdraw_and_withdrawn_is_hidden():
    catalog = Catalog()
    catalog.publish(dataset())
    with pytest.raises(AuthorizationError):
        catalog.withdraw("d1", "intruder")
    catalog.withdraw("d1", "a")
    assert catalog.search() == []
    with pytest.raises(NotFoundError):
        catalog.get("d1")
    assert catalog.get("d1", include_withdrawn=True).withdrawn
