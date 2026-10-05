"""Python client of a connector's management API."""

from __future__ import annotations

import base64
from typing import Any

import httpx

from dataspace.audit.chain import AuditEvent
from dataspace.common.http import call
from dataspace.policy.model import Action, Policy, Rule
from dataspace.protocol.catalog import DatasetOffer
from dataspace.protocol.negotiation import Negotiation
from dataspace.protocol.transfer import Transfer


class ConnectorClient:
    def __init__(self, base_url: str, api_key: str, http: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/") + "/management"
        self.http = http or httpx.Client(timeout=30)
        self.headers = {"X-Api-Key": api_key}

    def _call(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return call(self.http, method, self.base_url + path, headers=self.headers, **kwargs)

    def identity(self) -> dict:
        return self._call("GET", "/identity").json()

    @property
    def did(self) -> str:
        return self.identity()["did"]

    def catalog(self, q: str | None = None) -> list[DatasetOffer]:
        return [DatasetOffer.model_validate(o)
                for o in self._call("GET", "/catalog", params={"q": q} if q else None).json()]

    def publish(self, dataset_id: str, content: bytes, title: str, rules: list[Rule], **metadata: Any) -> dict:
        body = {"id": dataset_id, "title": title, "content_base64": base64.b64encode(content).decode(),
                "rules": [r.model_dump(mode="json") for r in rules], **metadata}
        return self._call("POST", "/datasets", json=body).json()

    def set_policy(self, dataset_id: str, rules: list[Rule]) -> Policy:
        body = {"rules": [r.model_dump(mode="json") for r in rules]}
        return Policy.model_validate(self._call("PUT", f"/datasets/{dataset_id}/policy", json=body).json())

    def withdraw(self, dataset_id: str) -> dict:
        return self._call("DELETE", f"/datasets/{dataset_id}").json()

    def negotiate(self, provider: str, dataset_id: str, action: Action | str,
                  purpose: str | None = None) -> Negotiation:
        body = {"provider": provider, "dataset_id": dataset_id, "action": Action(action).value,
                "purpose": purpose}
        return Negotiation.model_validate(self._call("POST", "/negotiations", json=body).json())

    def agreements(self) -> dict:
        return self._call("GET", "/agreements").json()

    def revoke(self, agreement_id: str, reason: str) -> dict:
        return self._call("POST", f"/agreements/{agreement_id}/revoke", json={"reason": reason}).json()

    def transfer(self, agreement_id: str) -> Transfer:
        return Transfer.model_validate(
            self._call("POST", "/transfers", json={"agreement_id": agreement_id}).json())

    def data(self, transfer_id: str) -> bytes:
        return self._call("GET", f"/transfers/{transfer_id}/data").content

    def audit(self) -> list[AuditEvent]:
        return [AuditEvent.model_validate(e) for e in self._call("GET", "/audit").json()]

    def verify_audit(self) -> dict:
        return self._call("GET", "/audit/verify").json()
