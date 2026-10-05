"""In-process deployment of a complete data space.

Runs the authority, the federated catalog, the transparency log and one
connector per participant inside a single Python process. Services talk
over HTTP exactly as in a real deployment; requests are routed in memory
instead of through the network. Used by the test suite, the demo and the
experiments; ``docker compose`` runs the same services as containers.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dataspace.client import ConnectorClient
from dataspace.common.http import call
from dataspace.identity.did import did_web
from dataspace.services.authority.app import Registry
from dataspace.services.authority.app import create_app as authority_app
from dataspace.services.base import ServiceContext
from dataspace.services.catalog.app import create_app as catalog_app
from dataspace.services.connector.app import create_app as connector_app
from dataspace.services.connector.control_plane import ControlPlane
from dataspace.services.connector.settings import ConnectorSettings, ParticipantProfile
from dataspace.services.transparency.app import create_app as transparency_app

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_URL = "http://authority:8000"
CATALOG_URL = "http://catalog:8000"
TRANSPARENCY_URL = "http://transparency:8000"


class RoutingTransport(httpx.BaseTransport):
    """Routes each request to the in-process service registered for its host."""

    def __init__(self) -> None:
        self.services: dict[str, TestClient] = {}

    def mount(self, base_url: str, app: FastAPI) -> None:
        self.services[httpx.URL(base_url).netloc.decode()] = TestClient(app)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        service = self.services.get(request.url.netloc.decode())
        if service is None:
            raise httpx.ConnectError(f"no service at {request.url.host}", request=request)
        response = service.request(request.method, request.url.raw_path.decode(),
                                   headers=dict(request.headers), content=request.read())
        return httpx.Response(response.status_code, headers=response.headers, content=response.content)


class LocalDataSpace:
    def __init__(self, participants_dir: str | Path = ROOT / "participants",
                 registry: str | Path = ROOT / "infrastructure/authority/registry.yaml",
                 admin_token: str = "admin-token"):
        self.transport = RoutingTransport()
        self.http = httpx.Client(transport=self.transport, timeout=None)
        self.admin_token = admin_token

        self.transport.mount(AUTHORITY_URL, authority_app(
            self._context(AUTHORITY_URL), Registry.load(registry), admin_token))
        self.transport.mount(CATALOG_URL, catalog_app(self._context(CATALOG_URL)))
        self.transport.mount(TRANSPARENCY_URL, transparency_app(self._context(TRANSPARENCY_URL)))

        self.control_planes: dict[str, ControlPlane] = {}
        self.clients: dict[str, ConnectorClient] = {}
        for path in sorted(Path(participants_dir).glob("*/config/participant.yaml")):
            name = path.parent.parent.name
            profile = ParticipantProfile.load(path)
            settings = ConnectorSettings(
                public_url=profile.endpoint, authority_url=AUTHORITY_URL, catalog_url=CATALOG_URL,
                transparency_url=TRANSPARENCY_URL, management_api_key=f"{name}-key",
                did_scheme="http", profile=profile,
            )
            app = connector_app(settings, self._context(profile.endpoint))
            self.transport.mount(profile.endpoint, app)
            self.control_planes[name] = app.state.control_plane
            self.clients[name] = ConnectorClient(profile.endpoint, settings.management_api_key, self.http)

    def _context(self, url: str) -> ServiceContext:
        return ServiceContext.create(url, http=self.http, did_scheme="http")

    def start(self) -> LocalDataSpace:
        """Onboard every connector (credentials) and publish its datasets."""
        for control_plane in self.control_planes.values():
            control_plane.bootstrap()
        return self

    def did(self, participant: str) -> str:
        return self.control_planes[participant].did

    @property
    def authority_did(self) -> str:
        return did_web(AUTHORITY_URL)

    def revoke_credentials(self, participant: str) -> list[str]:
        response = call(self.http, "POST", f"{AUTHORITY_URL}/credentials/revoke",
                        headers={"X-Admin-Token": self.admin_token}, json={"subject": self.did(participant)})
        return response.json()["revoked"]
