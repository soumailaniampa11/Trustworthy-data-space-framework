"""Trust anchor: attests verified facts about participants as verifiable credentials.

The authority keeps a registry of what it has verified out of band
(organisation, jurisdiction, sector, certifications). A participant proves
control of its DID with a presentation and receives credentials for exactly
those facts, never for what it claims about itself. Credentials can be
revoked through a signed revocation list.

Run: uvicorn --factory dataspace.services.authority.app:create_app_from_env
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, Header
from pydantic import BaseModel, Field

from dataspace.common.clock import utcnow
from dataspace.common.errors import Forbidden, NotFound, Unauthenticated
from dataspace.identity.credentials import (
    PresentationVerifier, RevocationList, VerifiableCredential, VerifiablePresentation, issue_credential,
)
from dataspace.services.base import ServiceContext, context_from_env, env, service_app


class RegistryEntry(BaseModel):
    did: str
    name: str
    organization: str
    credentials: dict[str, dict[str, Any]] = Field(default_factory=dict)
    """Credential type -> attested claims."""


class Registry(BaseModel):
    participants: list[RegistryEntry] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> Registry:
        return cls.model_validate(yaml.safe_load(Path(path).read_text()) or {})

    def get(self, did: str) -> RegistryEntry | None:
        return next((p for p in self.participants if p.did == did), None)


class Revocation(BaseModel):
    subject: str | None = None
    """Revoke every credential issued to this DID..."""
    credential_id: str | None = None
    """...or a single credential."""


class RevokedId(BaseModel):
    id: str


def create_app(ctx: ServiceContext, registry: Registry, admin_token: str,
               validity: timedelta = timedelta(days=365)):
    app = service_app(
        "Data Space Authority",
        "Trust anchor issuing verifiable credentials for verified participant facts.",
        ctx,
    )
    status_url = f"{ctx.public_url}/credentials/status"
    verifier = PresentationVerifier(ctx.resolver, ctx.http, trusted_issuers=set())

    def require_admin(x_admin_token: str = Header(default="")) -> None:
        if not secrets.compare_digest(x_admin_token, admin_token):
            raise Unauthenticated("invalid admin token")

    @app.get("/registry", tags=["registry"])
    def list_participants() -> list[dict[str, str]]:
        return [{"did": p.did, "name": p.name, "organization": p.organization}
                for p in registry.participants]

    @app.post("/credentials/request", response_model=list[VerifiableCredential],
              response_model_by_alias=True, response_model_exclude_none=True, tags=["credentials"])
    def request_credentials(presentation: VerifiablePresentation) -> list[VerifiableCredential]:
        """Issue the credentials of the presenting participant (DID control proven by the presentation)."""
        subject = verifier.verify(presentation, audience=ctx.did).did
        entry = registry.get(subject)
        if entry is None:
            raise Forbidden(f"{subject} has not been onboarded by this authority")
        issued = []
        for kind, claims in entry.credentials.items():
            vc = issue_credential(ctx.did, ctx.wallet.sign, subject, [kind], claims, validity, status_url)
            ctx.store.put("issued", vc.id, vc)
            issued.append(vc)
        return issued

    @app.get("/credentials/status", response_model=RevocationList, response_model_by_alias=True,
             response_model_exclude_none=True, tags=["credentials"])
    def revocation_list() -> RevocationList:
        revoked = [r.id for r in ctx.store.find("revoked", RevokedId)]
        status = RevocationList(id=status_url, issuer=ctx.did, updated=utcnow(), revoked=revoked)
        ctx.wallet.sign_document(status)
        return status

    @app.post("/credentials/revoke", dependencies=[Depends(require_admin)], tags=["credentials"])
    def revoke(body: Revocation) -> dict[str, list[str]]:
        targets = [
            vc.id for vc in ctx.store.find("issued", VerifiableCredential)
            if vc.id == body.credential_id or (body.subject and vc.subject == body.subject)
        ]
        if not targets:
            raise NotFound("no matching credential")
        for vc_id in targets:
            ctx.store.put("revoked", vc_id, RevokedId(id=vc_id))
        return {"revoked": targets}

    return app


def create_app_from_env():
    return create_app(
        context_from_env(),
        Registry.load(env("REGISTRY_PATH")),
        admin_token=env("ADMIN_TOKEN"),
    )
