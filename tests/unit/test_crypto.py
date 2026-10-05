from dataspace.common.crypto import KeyPair, canonical_json, verify
from dataspace.identity.proofs import Signed, check_proof, create_proof


class Doc(Signed):
    a: int
    b: str


def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": [2, {"d": 3, "c": 4}]}) == b'{"a":[2,{"c":4,"d":3}],"b":1}'


def test_signature_roundtrip():
    keys = KeyPair()
    signature = keys.sign(b"msg")
    assert verify(keys.public_key, b"msg", signature)
    assert not verify(keys.public_key, b"other", signature)
    assert not verify(KeyPair().public_key, b"msg", signature)
    assert not verify(keys.public_key, b"msg", "not-a-signature")


def test_document_proof_detects_any_change():
    keys = KeyPair()
    doc = Doc(a=1, b="x")
    doc.proof = create_proof(doc.signing_payload(), keys, "did:web:x#key-1")
    assert check_proof(doc.signing_payload(), doc.proof, keys.public_key)
    doc.a = 2
    assert not check_proof(doc.signing_payload(), doc.proof, keys.public_key)


def test_proof_options_are_signed():
    keys = KeyPair()
    doc = Doc(a=1, b="x")
    proof = create_proof(doc.signing_payload(), keys, "did:web:x#key-1", domain="did:web:alice")
    proof.domain = "did:web:mallory"
    assert not check_proof(doc.signing_payload(), proof, keys.public_key)


def test_key_persistence(tmp_path):
    path = tmp_path / "keys" / "connector.key"
    first = KeyPair.load_or_create(path)
    assert KeyPair.load_or_create(path).public_key == first.public_key
    assert oct(path.stat().st_mode & 0o777) == "0o600"
