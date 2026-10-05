import pytest

from dataspace.audit import merkle


def leaves(n: int) -> list[bytes]:
    return [merkle.leaf_hash(f"entry-{i}".encode()) for i in range(n)]


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 33])
def test_inclusion_proofs(size):
    tree = leaves(size)
    root = merkle.root(tree)
    for index in range(size):
        proof = merkle.inclusion_proof(index, tree)
        assert merkle.verify_inclusion(tree[index], index, size, proof, root)
        assert not merkle.verify_inclusion(merkle.leaf_hash(b"forged"), index, size, proof, root)
        assert len(proof) <= size.bit_length()  # O(log n)


@pytest.mark.parametrize("second", [2, 3, 5, 8, 13, 32])
def test_consistency_proofs(second):
    tree = leaves(second)
    for first in range(1, second + 1):
        proof = merkle.consistency_proof(first, tree)
        assert merkle.verify_consistency(first, second, merkle.root(tree[:first]), merkle.root(tree), proof)


def test_rewritten_history_is_inconsistent():
    honest = leaves(10)
    rewritten = [merkle.leaf_hash(b"rewritten")] + honest[1:]
    old_root = merkle.root(honest[:6])
    proof = merkle.consistency_proof(6, rewritten)
    assert not merkle.verify_consistency(6, 10, old_root, merkle.root(rewritten), proof)


def test_domain_separation_between_leaves_and_nodes():
    a, b = merkle.leaf_hash(b"a"), merkle.leaf_hash(b"b")
    assert merkle.leaf_hash(a + b) != merkle.node_hash(a, b)
