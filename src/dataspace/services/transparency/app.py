"""Transparency log: an append-only Merkle log of signed audit receipts (RFC 9162).

Participants anchor the hash of every local audit event here. Anyone can
obtain inclusion proofs (an event was logged) and consistency proofs (the
log only grew), checked against tree heads signed by the log. Neither a
participant nor the log operator can rewrite history without detection.

Run: uvicorn --factory dataspace.services.transparency.app:create_app_from_env
"""

from __future__ import annotations

import threading

from pydantic import BaseModel

from dataspace.audit import merkle
from dataspace.audit.receipts import (
    AppendResult, ConsistencyProof, InclusionProof, Receipt, SignedTreeHead,
)
from dataspace.common.clock import utcnow
from dataspace.common.crypto import canonical_json
from dataspace.common.errors import ProtocolError
from dataspace.services.base import ServiceContext, context_from_env, service_app


class LogEntry(BaseModel):
    index: int
    leaf_hash: str
    receipt: Receipt


def receipt_leaf(receipt: Receipt) -> bytes:
    return merkle.leaf_hash(canonical_json(receipt.model_dump(mode="json", exclude_none=True)))


def create_app(ctx: ServiceContext):
    app = service_app(
        "Transparency Log",
        "Append-only Merkle log of signed audit receipts (RFC 9162 proofs).",
        ctx,
    )
    lock = threading.Lock()
    leaves = [bytes.fromhex(e.leaf_hash) for e in ctx.store.find("entries", LogEntry)]

    def tree_head(size: int | None = None) -> SignedTreeHead:
        size = len(leaves) if size is None else size
        sth = SignedTreeHead(log=ctx.did, tree_size=size, root_hash=merkle.root(leaves[:size]).hex(),
                             timestamp=utcnow())
        ctx.wallet.sign_document(sth)
        return sth

    def check_size(size: int) -> None:
        if not 0 < size <= len(leaves):
            raise ProtocolError(f"tree size must be in [1, {len(leaves)}]")

    @app.post("/entries", response_model=AppendResult, status_code=201, tags=["log"])
    def append(receipt: Receipt) -> AppendResult:
        ctx.resolver.verify(receipt, expected_signer=receipt.actor)
        leaf = receipt_leaf(receipt)
        with lock:
            index = len(leaves)
            ctx.store.put("entries", str(index), LogEntry(index=index, leaf_hash=leaf.hex(), receipt=receipt))
            leaves.append(leaf)
            head = tree_head()
        return AppendResult(index=index, leaf_hash=leaf.hex(), tree_head=head)

    @app.get("/entries", response_model=list[LogEntry], tags=["log"])
    def entries(start: int = 0, end: int | None = None) -> list[LogEntry]:
        end = len(leaves) if end is None else min(end, len(leaves))
        return [ctx.store.get("entries", str(i), LogEntry) for i in range(start, end)]

    @app.get("/sth", response_model=SignedTreeHead, tags=["log"])
    def signed_tree_head() -> SignedTreeHead:
        with lock:
            return tree_head()

    @app.get("/proofs/inclusion", response_model=InclusionProof, tags=["proofs"])
    def inclusion(index: int, tree_size: int) -> InclusionProof:
        check_size(tree_size)
        if not 0 <= index < tree_size:
            raise ProtocolError("index outside the tree")
        path = merkle.inclusion_proof(index, leaves[:tree_size])
        return InclusionProof(index=index, tree_size=tree_size, leaf_hash=leaves[index].hex(),
                              path=[p.hex() for p in path])

    @app.get("/proofs/consistency", response_model=ConsistencyProof, tags=["proofs"])
    def consistency(first: int, second: int) -> ConsistencyProof:
        check_size(second)
        if not 0 < first <= second:
            raise ProtocolError("first must be in [1, second]")
        path = merkle.consistency_proof(first, leaves[:second])
        return ConsistencyProof(first=first, second=second, path=[p.hex() for p in path])

    return app


def create_app_from_env():
    return create_app(context_from_env())
