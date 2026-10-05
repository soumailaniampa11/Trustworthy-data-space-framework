"""Document store backed by SQLAlchemy (SQLite for tests, PostgreSQL in deployment).

Records are Pydantic models serialised as JSON, grouped in collections.
Insertion order is preserved, which the audit chain relies on.
"""

from __future__ import annotations

import threading
from typing import TypeVar

from pydantic import BaseModel
from sqlalchemy import (
    Column, Integer, MetaData, String, Table, Text, UniqueConstraint, create_engine, select, update,
)
from sqlalchemy.pool import StaticPool

from dataspace.common.errors import NotFound

M = TypeVar("M", bound=BaseModel)

_metadata = MetaData()
_documents = Table(
    "documents",
    _metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("collection", String(64), nullable=False),
    Column("id", String(512), nullable=False),
    Column("body", Text, nullable=False),
    UniqueConstraint("collection", "id"),
)


class DocumentStore:
    def __init__(self, url: str = "sqlite://"):
        options = {}
        if url.startswith("sqlite"):
            options = {"connect_args": {"check_same_thread": False}}
            if url in ("sqlite://", "sqlite:///:memory:"):
                options["poolclass"] = StaticPool
        self._engine = create_engine(url, **options)
        self._lock = threading.Lock()
        _metadata.create_all(self._engine)

    def put(self, collection: str, key: str, document: BaseModel) -> None:
        body = document.model_dump_json(by_alias=True)
        with self._lock, self._engine.begin() as conn:
            exists = conn.execute(
                select(_documents.c.seq).where(
                    _documents.c.collection == collection, _documents.c.id == key
                )
            ).first()
            if exists:
                conn.execute(
                    update(_documents).where(_documents.c.seq == exists.seq).values(body=body)
                )
            else:
                conn.execute(_documents.insert().values(collection=collection, id=key, body=body))

    def get(self, collection: str, key: str, model: type[M]) -> M:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(_documents.c.body).where(
                    _documents.c.collection == collection, _documents.c.id == key
                )
            ).first()
        if row is None:
            raise NotFound(f"{collection[:-1] if collection.endswith('s') else collection} '{key}' not found")
        return model.model_validate_json(row.body)

    def find(self, collection: str, model: type[M]) -> list[M]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(_documents.c.body)
                .where(_documents.c.collection == collection)
                .order_by(_documents.c.seq)
            ).all()
        return [model.model_validate_json(r.body) for r in rows]

    def count(self, collection: str) -> int:
        with self._engine.connect() as conn:
            return len(conn.execute(
                select(_documents.c.seq).where(_documents.c.collection == collection)
            ).all())
