"""Scaffolding shared by every service: identity, DID document, errors, health."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx
from fastapi import FastAPI

from dataspace import __version__
from dataspace.common.crypto import KeyPair
from dataspace.common.http import install_error_handlers
from dataspace.common.store import DocumentStore
from dataspace.identity.did import DIDDocument, DIDResolver, did_web
from dataspace.identity.wallet import Wallet


@dataclass
class ServiceContext:
    """Everything a service needs to act as a data space entity."""

    public_url: str
    wallet: Wallet
    http: httpx.Client
    resolver: DIDResolver
    store: DocumentStore

    @classmethod
    def create(
        cls,
        public_url: str,
        http: httpx.Client | None = None,
        database_url: str = "sqlite://",
        key_file: str | None = None,
        did_scheme: str = "https",
    ) -> ServiceContext:
        public_url = public_url.rstrip("/")
        http = http or httpx.Client(timeout=10)
        wallet = Wallet(did_web(public_url), KeyPair.load_or_create(key_file))
        return cls(public_url, wallet, http, DIDResolver(http, did_scheme), DocumentStore(database_url))

    @property
    def did(self) -> str:
        return self.wallet.did


def service_app(title: str, description: str, ctx: ServiceContext,
                services: dict[str, str] | None = None, **kwargs) -> FastAPI:
    app = FastAPI(title=title, description=description, version=__version__, **kwargs)
    app.state.ctx = ctx
    install_error_handlers(app)
    document = ctx.wallet.did_document(services)

    @app.get("/.well-known/did.json", response_model=DIDDocument, response_model_by_alias=True,
             response_model_exclude_none=True, tags=["identity"])
    def did_document() -> DIDDocument:
        return document

    @app.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        return {"status": "ok", "did": ctx.did, "version": __version__}

    return app


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"environment variable {name} is required")
    return value


def context_from_env() -> ServiceContext:
    return ServiceContext.create(
        public_url=env("PUBLIC_URL"),
        database_url=env("DATABASE_URL", "sqlite://"),
        key_file=os.environ.get("KEY_FILE"),
        did_scheme=env("DID_SCHEME", "https"),
    )
