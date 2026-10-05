"""Merkle tree hashing and proofs, as specified in RFC 9162 (Certificate Transparency 2.0).

* ``inclusion_proof`` proves that an entry is in the log;
* ``consistency_proof`` proves that a later tree extends an earlier one,
  i.e. that the log is append-only and history was not rewritten.

Hashes are raw bytes internally and hex strings at the API boundary.
"""

from __future__ import annotations

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash (MTH) of a list of leaf hashes."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(index: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [root(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], expected_root: bytes) -> bool:
    """RFC 9162, section 2.1.3.2."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root(leaves[:k])]


def consistency_proof(first: int, leaves: list[bytes]) -> list[bytes]:
    if not 0 < first <= len(leaves):
        raise ValueError("invalid tree sizes")
    return _subproof(first, leaves, True)


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: list[bytes]) -> bool:
    """RFC 9162, section 2.1.4.2."""
    if first == second:
        return not proof and first_root == second_root
    if not 0 < first < second or not proof:
        return False
    if first & (first - 1) == 0:  # exact power of two
        proof = [first_root, *proof]
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
