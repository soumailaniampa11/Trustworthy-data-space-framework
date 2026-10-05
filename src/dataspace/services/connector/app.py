"""Connector service.

Two APIs with distinct trust boundaries:

* ``/dsp/*``         protocol API, called by other connectors; callers are
                     authenticated by signed presentations in the messages.
* ``/management/*``  management API, called only by the participant itself;
                     protected by an API key.

Run: uvicorn --factory dataspace.services.connector.app:create_app_from_env
"""

from __future__ import annotations

import base64
import logging
import secrets
import threading
import time
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel, Field

from dataspace.audit.chain import AuditEvent
from dataspace.common.errors import DataSpaceError, Unauthenticated
from dataspace.identity.credentials import VerifiableCredential
from dataspace.policy.model import Action, Policy, Rule
from dataspace.protocol.catalog import DatasetOffer
from dataspace.protocol.negotiation import (
    AgreementRecord, AgreementVerification, ContractAgreement, ContractRequest, Negotiation,
    NegotiationResponse,
)
from dataspace.protocol.transfer import Transfer, TransferRequest, TransferResponse
from dataspace.services.base import ServiceContext, service_app
from dataspace.services.connector.control_plane import (
    PROTOCOL_SERVICE, AuditReport, ControlPlane, LocalDataset, attestation_header,
)
from dataspace.services.connector.settings import ConnectorSettings

log = logging.getLogger("dataspace.connector")


class PublishDataset(BaseModel):
    id: str
    title: str
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    media_type: str = "application/octet-stream"
    sensitivity: str = "internal"
    license: str | None = None
    content_base64: str
    rules: list[Rule] = Field(default_factory=list)


class PolicyUpdate(BaseModel):
    rules: list[Rule]


class StartNegotiation(BaseModel):
    provider: str
    dataset_id: str
    action: Action
    purpose: str | None = None


class StartTransfer(BaseModel):
    agreement_id: str


class Revoke(BaseModel):
    reason: str = "revoked by provider"


class Agreements(BaseModel):
    as_provider: list[AgreementRecord]
    as_consumer: list[ContractAgreement]


class Identity(BaseModel):
    did: str
    credentials: list[VerifiableCredential]


def protocol_router(cp: ControlPlane) -> APIRouter:
    router = APIRouter(prefix="/dsp", tags=["protocol (connector to connector)"])

    @router.post("/negotiations/request", response_model=NegotiationResponse)
    def contract_request(request: ContractRequest) -> NegotiationResponse:
        return cp.handle_contract_request(request)

    @router.post("/negotiations/{negotiation_id}/verification", response_model=NegotiationResponse)
    def agreement_verification(negotiation_id: str, body: AgreementVerification) -> NegotiationResponse:
        return cp.handle_agreement_verification(negotiation_id, body)

    @router.post("/transfers/request", response_model=TransferResponse)
    def transfer_request(request: TransferRequest) -> TransferResponse:
        return cp.handle_transfer_request(request)

    @router.get("/data/{transfer_id}", tags=["data plane"])
    def data(transfer_id: str, authorization: str = Header(default="")) -> Response:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise Unauthenticated("missing data address token")
        content, attestation = cp.serve_data(transfer_id, token)
        return Response(content, media_type="application/octet-stream",
                        headers={"X-Data-Attestation": attestation_header(attestation)})

    return router


def management_router(cp: ControlPlane, api_key: str) -> APIRouter:
    def require_key(x_api_key: str = Header(default="")) -> None:
        if not secrets.compare_digest(x_api_key, api_key):
            raise Unauthenticated("invalid management API key")

    router = APIRouter(prefix="/management", tags=["management (participant only)"],
                       dependencies=[Depends(require_key)])

    @router.get("/identity", response_model=Identity, response_model_by_alias=True,
                response_model_exclude_none=True)
    def identity() -> Identity:
        return Identity(did=cp.did, credentials=cp.ctx.wallet.credentials)

    @router.post("/identity/refresh", response_model=Identity, response_model_by_alias=True,
                 response_model_exclude_none=True)
    def refresh_identity() -> Identity:
        cp.obtain_credentials()
        return identity()

    @router.get("/catalog", response_model=list[DatasetOffer])
    def catalog(q: str | None = None) -> list[DatasetOffer]:
        return cp.catalog(q)

    @router.get("/datasets", response_model=list[LocalDataset])
    def datasets() -> list[LocalDataset]:
        return cp.datasets()

    @router.post("/datasets", response_model=LocalDataset, status_code=201)
    def publish(body: PublishDataset) -> LocalDataset:
        metadata = body.model_dump(exclude={"id", "content_base64", "rules"})
        return cp.publish(body.id, base64.b64decode(body.content_base64), metadata, body.rules)

    @router.put("/datasets/{dataset_id}/policy", response_model=Policy)
    def set_policy(dataset_id: str, body: PolicyUpdate) -> Policy:
        return cp.set_policy(dataset_id, body.rules)

    @router.delete("/datasets/{dataset_id}", response_model=LocalDataset)
    def withdraw(dataset_id: str) -> LocalDataset:
        return cp.withdraw(dataset_id)

    @router.post("/negotiations", response_model=Negotiation, status_code=201)
    def negotiate(body: StartNegotiation) -> Negotiation:
        return cp.negotiate(body.provider, body.dataset_id, body.action, body.purpose)

    @router.get("/negotiations", response_model=list[Negotiation])
    def negotiations() -> list[Negotiation]:
        return cp.ctx.store.find("negotiations", Negotiation)

    @router.get("/agreements", response_model=Agreements)
    def agreements() -> Agreements:
        return Agreements(as_provider=cp.ctx.store.find("agreements", AgreementRecord),
                          as_consumer=cp.ctx.store.find("contracts", ContractAgreement))

    @router.post("/agreements/{agreement_id}/revoke", response_model=AgreementRecord)
    def revoke(agreement_id: str, body: Revoke) -> AgreementRecord:
        return cp.revoke_agreement(agreement_id, body.reason)

    @router.post("/transfers", response_model=Transfer, status_code=201)
    def transfer(body: StartTransfer) -> Transfer:
        return cp.transfer(body.agreement_id)

    @router.get("/transfers", response_model=list[Transfer])
    def transfers() -> list[Transfer]:
        return cp.ctx.store.find("transfers", Transfer)

    @router.get("/transfers/{transfer_id}/data")
    def received(transfer_id: str) -> Response:
        return Response(cp.received(transfer_id), media_type="application/octet-stream")

    @router.get("/audit", response_model=list[AuditEvent])
    def audit() -> list[AuditEvent]:
        return cp.audit.events()

    @router.get("/audit/verify", response_model=AuditReport)
    def verify_audit() -> AuditReport:
        return cp.verify_audit()

    return router


def _bootstrap_with_retry(cp: ControlPlane, attempts: int = 30, delay: float = 2.0) -> None:
    for attempt in range(1, attempts + 1):
        try:
            cp.bootstrap()
            log.info("connector %s bootstrapped", cp.did)
            return
        except DataSpaceError as exc:
            log.warning("bootstrap attempt %d/%d failed: %s", attempt, attempts, exc.detail)
            time.sleep(delay)
    log.error("connector %s could not bootstrap", cp.did)


def create_app(settings: ConnectorSettings, ctx: ServiceContext | None = None,
               auto_bootstrap: bool = False):
    ctx = ctx or ServiceContext.create(settings.public_url, database_url=settings.database_url,
                                       key_file=settings.key_file, did_scheme=settings.did_scheme)
    cp = ControlPlane(ctx, settings)

    @asynccontextmanager
    async def lifespan(app):
        if auto_bootstrap:  # other services resolve our DID: we must be serving first
            threading.Thread(target=_bootstrap_with_retry, args=(cp,), daemon=True).start()
        yield

    name = settings.profile.name if settings.profile else ctx.did
    app = service_app(f"Connector — {name}", "Participant connector (control plane and data plane).",
                      ctx, services={PROTOCOL_SERVICE: cp.protocol_endpoint}, lifespan=lifespan)
    app.state.control_plane = cp
    app.include_router(protocol_router(cp))
    app.include_router(management_router(cp, settings.management_api_key))
    return app


def create_app_from_env():
    logging.basicConfig(level=logging.INFO)
    return create_app(ConnectorSettings.from_env(), auto_bootstrap=True)
