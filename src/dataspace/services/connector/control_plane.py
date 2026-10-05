"""Control plane of a connector: the participant's agent in the data space.

As a **provider** it publishes signed offers, decides contract requests
(policy decision point), countersigns agreements and enforces them at every
transfer (policy enforcement point). As a **consumer** it negotiates
contracts, verifies what it receives and keeps the evidence. Every step is
recorded in the local audit trail, anchored in the transparency log.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
from datetime import datetime

import httpx
from pydantic import BaseModel, Field

from dataspace.audit import merkle
from dataspace.audit.chain import Anchor, AuditEvent, AuditTrail, Outcome
from dataspace.audit.receipts import AppendResult, ConsistencyProof, InclusionProof, Receipt, SignedTreeHead
from dataspace.common.blobs import storage_from_url
from dataspace.common.clock import utcnow
from dataspace.common.crypto import canonical_json, sha256_hex
from dataspace.common.errors import (
    DataSpaceError, Forbidden, IntegrityViolation, NotFound, PolicyViolation, ProtocolError, UpstreamError,
)
from dataspace.common.http import call
from dataspace.identity.credentials import PresentationVerifier, VerifiableCredential, VerifiedSubject
from dataspace.identity.did import did_web
from dataspace.policy.evaluator import Decision, EvaluationContext, PolicyEvaluator
from dataspace.policy.model import Action, Policy, Rule
from dataspace.policy.odrl import to_odrl
from dataspace.protocol.catalog import DatasetOffer
from dataspace.protocol.negotiation import (
    AgreementRecord, AgreementVerification, ContractAgreement, ContractRequest, Negotiation,
    NegotiationResponse, NegotiationState, new_id,
)
from dataspace.protocol.transfer import (
    DataAddress, DataAttestation, Transfer, TransferRequest, TransferResponse, TransferState,
)
from dataspace.services.base import ServiceContext
from dataspace.services.connector.settings import ConnectorSettings

PROTOCOL_SERVICE = "DataSpaceProtocol"


class LocalDataset(BaseModel):
    id: str
    title: str
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    media_type: str = "application/octet-stream"
    sensitivity: str = "internal"
    license: str | None = None
    checksum: str
    byte_size: int
    policy: Policy
    published: datetime
    withdrawn: bool = False


class _PendingAddress(BaseModel):
    token: str
    expires: datetime
    agreement_id: str
    dataset_id: str


class AuditReport(BaseModel):
    events: int
    anchored: int
    verified_inclusions: int
    tree_size: int
    root_hash: str
    consistent_with_previous: bool | None = None


class ControlPlane:
    def __init__(self, ctx: ServiceContext, settings: ConnectorSettings):
        self.ctx = ctx
        self.settings = settings
        self.blobs = storage_from_url(settings.storage_url)
        self.authority = did_web(settings.authority_url)
        self.verifier = PresentationVerifier(
            ctx.resolver, ctx.http, set(settings.trusted_issuers or [self.authority])
        )
        self.evaluator = PolicyEvaluator()
        self.audit = AuditTrail(ctx.store, anchor=self._anchor)
        self._addresses: dict[str, _PendingAddress] = {}
        self._lock = threading.Lock()
        self.ctx.wallet.credentials = ctx.store.find("credentials", VerifiableCredential)

    @property
    def did(self) -> str:
        return self.ctx.did

    @property
    def http(self) -> httpx.Client:
        return self.ctx.http

    # ------------------------------------------------------------------ onboarding

    def bootstrap(self) -> None:
        """Obtain credentials and (re-)publish the datasets of the participant profile."""
        self.obtain_credentials()
        profile = self.settings.profile
        if not profile:
            return
        for spec in profile.datasets:
            try:
                dataset = self.dataset(spec.id)
                self._publish_offer(dataset)
            except NotFound:
                content = ((profile.base_dir or ".") / spec.source).read_bytes() \
                    if profile.base_dir else b""
                self.publish(spec.id, content, spec.model_dump(exclude={"id", "source", "rules"}), spec.rules)

    def obtain_credentials(self) -> list[VerifiableCredential]:
        presentation = self.ctx.wallet.present(self.authority, credentials=[])
        response = call(self.http, "POST", f"{self.settings.authority_url}/credentials/request",
                        json=presentation.model_dump(mode="json", by_alias=True, exclude_none=True))
        credentials = [VerifiableCredential.model_validate(c) for c in response.json()]
        for vc in credentials:
            self.verifier.verify_credential(vc, self.did)
            self.ctx.store.put("credentials", vc.id, vc)
        self.ctx.wallet.credentials = credentials
        self.audit.record(self.did, "identity.credentials_obtained", self.authority,
                          types=[t for vc in credentials for t in vc.type[1:]])
        return credentials

    # ------------------------------------------------------------------ provider: publication

    def datasets(self) -> list[LocalDataset]:
        return self.ctx.store.find("datasets", LocalDataset)

    def dataset(self, dataset_id: str) -> LocalDataset:
        return self.ctx.store.get("datasets", dataset_id, LocalDataset)

    def publish(self, dataset_id: str, content: bytes, metadata: dict, rules: list[Rule]) -> LocalDataset:
        try:
            self.dataset(dataset_id)
            raise ProtocolError(f"dataset '{dataset_id}' already exists")
        except NotFound:
            pass
        self.blobs.put(f"datasets/{dataset_id}", content)
        dataset = LocalDataset(
            id=dataset_id, checksum=sha256_hex(content), byte_size=len(content),
            policy=self._policy(dataset_id, rules, version=1), published=utcnow(), **metadata,
        )
        self.ctx.store.put("datasets", dataset_id, dataset)
        self.audit.record(self.did, "dataset.published", dataset_id, checksum=dataset.checksum,
                          policy=dataset.policy.uid)
        self._publish_offer(dataset)
        return dataset

    def set_policy(self, dataset_id: str, rules: list[Rule]) -> Policy:
        dataset = self.dataset(dataset_id)
        dataset.policy = self._policy(dataset_id, rules, version=dataset.policy.version + 1)
        self.ctx.store.put("datasets", dataset_id, dataset)
        self.audit.record(self.did, "policy.updated", dataset_id, policy=dataset.policy.uid)
        self._publish_offer(dataset)
        return dataset.policy

    def withdraw(self, dataset_id: str) -> LocalDataset:
        dataset = self.dataset(dataset_id)
        dataset.withdrawn = True
        self.ctx.store.put("datasets", dataset_id, dataset)
        self.audit.record(self.did, "dataset.withdrawn", dataset_id)
        self._publish_offer(dataset)
        return dataset

    def _policy(self, dataset_id: str, rules: list[Rule], version: int) -> Policy:
        return Policy(uid=f"urn:policy:{dataset_id}:v{version}", assigner=self.did,
                      target=dataset_id, version=version, rules=rules)

    def _publish_offer(self, dataset: LocalDataset) -> None:
        offer = DatasetOffer(
            id=dataset.id, title=dataset.title, description=dataset.description,
            keywords=dataset.keywords, media_type=dataset.media_type, sensitivity=dataset.sensitivity,
            license=dataset.license, byte_size=dataset.byte_size, checksum=dataset.checksum,
            provider=self.did, endpoint=self.protocol_endpoint, policy=to_odrl(dataset.policy),
            issued=utcnow(), withdrawn=dataset.withdrawn,
        )
        self.ctx.wallet.sign_document(offer)
        call(self.http, "POST", f"{self.settings.catalog_url}/offers", json=offer.model_dump(mode="json"))

    @property
    def protocol_endpoint(self) -> str:
        return f"{self.ctx.public_url}/dsp"

    # ------------------------------------------------------------------ provider: negotiation (PDP)

    def _usage_count(self, consumer: str, dataset_id: str) -> int:
        return sum(r.uses for r in self.ctx.store.find("agreements", AgreementRecord)
                   if r.agreement.consumer == consumer and r.agreement.dataset_id == dataset_id)

    def _decide(self, subject: VerifiedSubject, dataset: LocalDataset, action: Action,
                purpose: str | None) -> Decision:
        ctx = EvaluationContext(subject=subject, action=action, purpose=purpose,
                                usage_count=self._usage_count(subject.did, dataset.id))
        return self.evaluator.evaluate(dataset.policy, ctx)

    def handle_contract_request(self, request: ContractRequest) -> NegotiationResponse:
        try:
            subject = self.verifier.verify(request.presentation, audience=self.did,
                                           expected_holder=request.consumer)
        except DataSpaceError as exc:
            self.audit.record(request.consumer, "contract.requested", request.dataset_id, Outcome.DENIED,
                              negotiation=request.negotiation_id, reason=f"identity: {exc.detail}")
            raise
        dataset = self.dataset(request.dataset_id)
        if dataset.withdrawn:
            raise NotFound(f"dataset '{dataset.id}' has been withdrawn")

        now = utcnow()
        negotiation = Negotiation(
            id=request.negotiation_id, role="provider", counterparty=request.consumer,
            dataset_id=dataset.id, action=request.action, purpose=request.purpose,
            state=NegotiationState.TERMINATED, created=now, updated=now,
        )
        if request.policy_uid != dataset.policy.uid:
            decision = Decision(permitted=False,
                                reason=f"offer {request.policy_uid} is outdated, current is {dataset.policy.uid}")
        else:
            decision = self._decide(subject, dataset, request.action, request.purpose)

        if not decision.permitted:
            negotiation.reason = decision.reason
            self.ctx.store.put("negotiations", negotiation.id, negotiation)
            self.audit.record(request.consumer, "contract.requested", dataset.id, Outcome.DENIED,
                              negotiation=negotiation.id, action=request.action.value,
                              purpose=request.purpose, claims=subject.claims, reason=decision.reason)
            return NegotiationResponse(negotiation_id=negotiation.id, state=negotiation.state,
                                       reason=decision.reason)

        agreement = ContractAgreement(
            id=new_id("agr"), negotiation_id=negotiation.id, provider=self.did,
            consumer=request.consumer, dataset_id=dataset.id, checksum=dataset.checksum,
            action=request.action, purpose=request.purpose, policy_uid=dataset.policy.uid,
            policy_version=dataset.policy.version, rule_id=decision.rule_id,
            obligations=decision.obligations, valid_until=now + self.settings.agreement_validity,
            issued=now,
        )
        self.ctx.wallet.sign_document(agreement)
        negotiation.state, negotiation.reason, negotiation.agreement = (
            NegotiationState.AGREED, decision.reason, agreement)
        self.ctx.store.put("negotiations", negotiation.id, negotiation)
        self.audit.record(request.consumer, "contract.requested", dataset.id, Outcome.SUCCESS,
                          negotiation=negotiation.id, action=request.action.value, purpose=request.purpose,
                          claims=subject.claims, rule=decision.rule_id)
        return NegotiationResponse(negotiation_id=negotiation.id, state=negotiation.state,
                                   reason=decision.reason, agreement=agreement)

    def handle_agreement_verification(self, negotiation_id: str,
                                      verification: AgreementVerification) -> NegotiationResponse:
        negotiation = self.ctx.store.get("negotiations", negotiation_id, Negotiation)
        if negotiation.role != "provider" or negotiation.state != NegotiationState.AGREED:
            raise ProtocolError(f"negotiation {negotiation_id} is {negotiation.state.value}")
        agreement = negotiation.agreement
        assert agreement is not None
        self.ctx.resolver.verify(agreement, expected_signer=agreement.consumer,
                                 proof=verification.consumer_proof)
        agreement.consumer_proof = verification.consumer_proof
        negotiation.state, negotiation.updated = NegotiationState.FINALIZED, utcnow()
        self.ctx.store.put("negotiations", negotiation.id, negotiation)
        self.ctx.store.put("agreements", agreement.id, AgreementRecord(agreement=agreement))
        self.audit.record(agreement.consumer, "contract.finalized", agreement.dataset_id,
                          agreement=agreement.id, digest=self._digest(agreement))
        return NegotiationResponse(negotiation_id=negotiation.id, state=negotiation.state,
                                   agreement=agreement)

    @staticmethod
    def _digest(agreement: ContractAgreement) -> str:
        return sha256_hex(canonical_json(agreement.model_dump(mode="json", exclude_none=True)))

    # ------------------------------------------------------------------ provider: enforcement (PEP)

    def agreement_record(self, agreement_id: str) -> AgreementRecord:
        return self.ctx.store.get("agreements", agreement_id, AgreementRecord)

    def revoke_agreement(self, agreement_id: str, reason: str) -> AgreementRecord:
        record = self.agreement_record(agreement_id)
        record.revoked, record.revocation_reason = True, reason
        self.ctx.store.put("agreements", agreement_id, record)
        self.audit.record(self.did, "contract.revoked", record.agreement.dataset_id,
                          agreement=agreement_id, reason=reason)
        return record

    def handle_transfer_request(self, request: TransferRequest) -> TransferResponse:
        record = self.agreement_record(request.agreement_id)
        agreement = record.agreement
        if agreement.consumer != request.consumer:
            raise Forbidden("agreement belongs to another participant")
        subject = self.verifier.verify(request.presentation, audience=self.did,
                                       expected_holder=request.consumer)

        def deny(reason: str, error: type[DataSpaceError] = Forbidden):
            self.audit.record(request.consumer, "transfer.requested", agreement.dataset_id, Outcome.DENIED,
                              agreement=agreement.id, transfer=request.transfer_id, reason=reason)
            raise error(reason)

        if record.revoked:
            deny(f"agreement revoked: {record.revocation_reason}")
        if agreement.valid_until and utcnow() > agreement.valid_until:
            deny("agreement expired")
        try:
            dataset = self.dataset(agreement.dataset_id)
        except NotFound:
            dataset = None
        if dataset is None or dataset.withdrawn:
            deny("dataset withdrawn")
        assert dataset is not None
        if dataset.checksum != agreement.checksum:
            deny("dataset content changed since the agreement", IntegrityViolation)

        # Continuous usage control: the *current* policy and the *current* claims decide.
        decision = self._decide(subject, dataset, agreement.action, agreement.purpose)
        if not decision.permitted:
            deny(decision.reason, PolicyViolation)

        record.uses += 1
        self.ctx.store.put("agreements", agreement.id, record)
        now = utcnow()
        address = _PendingAddress(token=secrets.token_urlsafe(32), expires=now + self.settings.data_address_ttl,
                                  agreement_id=agreement.id, dataset_id=dataset.id)
        with self._lock:
            self._addresses[request.transfer_id] = address
        self.ctx.store.put("transfers", request.transfer_id, Transfer(
            id=request.transfer_id, role="provider", agreement_id=agreement.id, dataset_id=dataset.id,
            counterparty=request.consumer, state=TransferState.STARTED, checksum=dataset.checksum,
            size=dataset.byte_size, created=now,
        ))
        self.audit.record(request.consumer, "transfer.started", dataset.id, agreement=agreement.id,
                          transfer=request.transfer_id, use=record.uses, rule=decision.rule_id)
        return TransferResponse(
            transfer_id=request.transfer_id, state=TransferState.STARTED,
            data_address=DataAddress(endpoint=f"{self.protocol_endpoint}/data/{request.transfer_id}",
                                     token=address.token, expires=address.expires),
        )

    # ------------------------------------------------------------------ provider: data plane

    def serve_data(self, transfer_id: str, token: str) -> tuple[bytes, DataAttestation]:
        with self._lock:
            address = self._addresses.pop(transfer_id, None)  # single use
        if address is None or not secrets.compare_digest(address.token, token):
            raise Forbidden("invalid or already used data address")
        if utcnow() > address.expires:
            raise Forbidden("data address expired")
        content = self.blobs.get(f"datasets/{address.dataset_id}")
        attestation = DataAttestation(transfer_id=transfer_id, dataset_id=address.dataset_id,
                                      checksum=sha256_hex(content))
        self.ctx.wallet.sign_document(attestation)
        transfer = self.ctx.store.get("transfers", transfer_id, Transfer)
        transfer.state, transfer.completed = TransferState.COMPLETED, utcnow()
        self.ctx.store.put("transfers", transfer_id, transfer)
        self.audit.record(transfer.counterparty, "transfer.served", address.dataset_id,
                          transfer=transfer_id, checksum=attestation.checksum)
        return content, attestation

    # ------------------------------------------------------------------ consumer

    def catalog(self, q: str | None = None) -> list[DatasetOffer]:
        response = call(self.http, "GET", f"{self.settings.catalog_url}/offers", params={"q": q} if q else None)
        return [DatasetOffer.model_validate(o) for o in response.json()]

    def negotiate(self, provider: str, dataset_id: str, action: Action, purpose: str | None) -> Negotiation:
        offer = DatasetOffer.model_validate(call(
            self.http, "GET", f"{self.settings.catalog_url}/offers/item",
            params={"provider": provider, "id": dataset_id}).json())
        self.ctx.resolver.verify(offer, expected_signer=provider)  # do not trust the catalog

        now = utcnow()
        negotiation = Negotiation(id=new_id("neg"), role="consumer", counterparty=provider,
                                  dataset_id=dataset_id, action=action, purpose=purpose,
                                  state=NegotiationState.REQUESTED, created=now, updated=now)
        request = ContractRequest(
            negotiation_id=negotiation.id, consumer=self.did, dataset_id=dataset_id,
            policy_uid=offer.policy["uid"], action=action, purpose=purpose,
            presentation=self.ctx.wallet.present(provider),
        )
        response = NegotiationResponse.model_validate(call(
            self.http, "POST", f"{offer.endpoint}/negotiations/request",
            json=request.model_dump(mode="json", by_alias=True, exclude_none=True)).json())

        negotiation.state, negotiation.reason = response.state, response.reason
        if response.state == NegotiationState.AGREED and response.agreement:
            agreement = response.agreement
            self._check_agreement(agreement, request, offer)
            consumer_proof = self.ctx.wallet.sign(agreement.signing_payload())
            final = NegotiationResponse.model_validate(call(
                self.http, "POST", f"{offer.endpoint}/negotiations/{negotiation.id}/verification",
                json=AgreementVerification(consumer_proof=consumer_proof).model_dump(mode="json")).json())
            agreement.consumer_proof = consumer_proof
            negotiation.state, negotiation.agreement = final.state, agreement
            self.ctx.store.put("contracts", agreement.id, agreement)

        negotiation.updated = utcnow()
        self.ctx.store.put("negotiations", negotiation.id, negotiation)
        finalized = negotiation.state == NegotiationState.FINALIZED
        self.audit.record(self.did, "contract.negotiated", dataset_id,
                          Outcome.SUCCESS if finalized else Outcome.DENIED,
                          negotiation=negotiation.id, provider=provider, action=action.value,
                          agreement=negotiation.agreement.id if negotiation.agreement else None,
                          digest=self._digest(negotiation.agreement) if negotiation.agreement else None,
                          reason=negotiation.reason)
        return negotiation

    def _check_agreement(self, agreement: ContractAgreement, request: ContractRequest,
                         offer: DatasetOffer) -> None:
        self.ctx.resolver.verify(agreement, expected_signer=offer.provider)
        expected = {
            "negotiation_id": request.negotiation_id, "consumer": self.did, "provider": offer.provider,
            "dataset_id": request.dataset_id, "action": request.action, "purpose": request.purpose,
            "checksum": offer.checksum,
        }
        for field, value in expected.items():
            if getattr(agreement, field) != value:
                raise IntegrityViolation(f"agreement field '{field}' does not match the request")

    def contract(self, agreement_id: str) -> ContractAgreement:
        return self.ctx.store.get("contracts", agreement_id, ContractAgreement)

    def transfer(self, agreement_id: str) -> Transfer:
        agreement = self.contract(agreement_id)
        endpoint = self.ctx.resolver.resolve(agreement.provider).endpoint(PROTOCOL_SERVICE)
        if endpoint is None:
            raise ProtocolError(f"{agreement.provider} exposes no protocol endpoint")
        transfer = Transfer(id=new_id("tx"), role="consumer", agreement_id=agreement.id,
                            dataset_id=agreement.dataset_id, counterparty=agreement.provider,
                            state=TransferState.REQUESTED, created=utcnow())
        request = TransferRequest(transfer_id=transfer.id, agreement_id=agreement.id, consumer=self.did,
                                  presentation=self.ctx.wallet.present(agreement.provider))
        try:
            response = TransferResponse.model_validate(call(
                self.http, "POST", f"{endpoint}/transfers/request",
                json=request.model_dump(mode="json", by_alias=True, exclude_none=True)).json())
            assert response.data_address is not None
            content, attestation = self._pull(response.data_address)
            self.ctx.resolver.verify(attestation, expected_signer=agreement.provider)
            checksum = sha256_hex(content)
            if attestation.transfer_id != transfer.id or attestation.checksum != checksum:
                raise IntegrityViolation("provider attestation does not match the received data")
            if checksum != agreement.checksum:
                raise IntegrityViolation("received data differs from the data agreed upon")
        except DataSpaceError as exc:
            transfer.state, transfer.reason = TransferState.TERMINATED, exc.detail
            self.ctx.store.put("transfers", transfer.id, transfer)
            outcome = Outcome.FAILURE if isinstance(exc, (IntegrityViolation, UpstreamError)) else Outcome.DENIED
            self.audit.record(self.did, "transfer.received", agreement.dataset_id, outcome,
                              agreement=agreement.id, transfer=transfer.id,
                              error=type(exc).__name__, reason=exc.detail)
            raise

        self.blobs.put(f"received/{transfer.id}", content)
        transfer.state, transfer.checksum, transfer.size, transfer.completed = (
            TransferState.COMPLETED, checksum, len(content), utcnow())
        self.ctx.store.put("transfers", transfer.id, transfer)
        self.audit.record(self.did, "transfer.received", agreement.dataset_id, agreement=agreement.id,
                          transfer=transfer.id, checksum=checksum, size=len(content))
        return transfer

    def _pull(self, address: DataAddress) -> tuple[bytes, DataAttestation]:
        response = call(self.http, "GET", address.endpoint,
                        headers={"Authorization": f"Bearer {address.token}"})
        header = response.headers.get("X-Data-Attestation")
        if not header:
            raise IntegrityViolation("provider did not attest the data")
        attestation = DataAttestation.model_validate_json(base64.urlsafe_b64decode(header))
        return response.content, attestation

    def received(self, transfer_id: str) -> bytes:
        transfer = self.ctx.store.get("transfers", transfer_id, Transfer)
        if transfer.role != "consumer" or transfer.state != TransferState.COMPLETED:
            raise NotFound(f"no data received for transfer {transfer_id}")
        return self.blobs.get(f"received/{transfer_id}")

    # ------------------------------------------------------------------ accountability

    def _anchor(self, event: AuditEvent) -> Anchor | None:
        receipt = Receipt(actor=self.did, event_type=event.event_type, subject=event.subject,
                          digest=event.hash, timestamp=event.timestamp)
        self.ctx.wallet.sign_document(receipt)
        try:
            result = AppendResult.model_validate(call(
                self.http, "POST", f"{self.settings.transparency_url}/entries",
                json=receipt.model_dump(mode="json", exclude_none=True)).json())
        except DataSpaceError:
            return None  # the event stays in the local chain; anchoring is best effort
        return Anchor(index=result.index, leaf_hash=result.leaf_hash)

    def verify_audit(self) -> AuditReport:
        """Verify the local chain, its anchoring in the log, and that the log only grew."""
        events = self.audit.events()
        self.audit.verify()
        log = self.settings.transparency_url
        sth = SignedTreeHead.model_validate(call(self.http, "GET", f"{log}/sth").json())
        self.ctx.resolver.verify(sth, expected_signer=did_web(log))
        root = bytes.fromhex(sth.root_hash)

        verified = 0
        anchored = [e for e in events if e.anchor]
        for event in anchored:
            assert event.anchor is not None
            entry = call(self.http, "GET", f"{log}/entries",
                         params={"start": event.anchor.index, "end": event.anchor.index + 1}).json()[0]
            receipt = Receipt.model_validate(entry["receipt"])
            if receipt.digest != event.hash or receipt.actor != self.did:
                raise IntegrityViolation(f"log entry {event.anchor.index} does not commit to event {event.sequence}")
            proof = InclusionProof.model_validate(call(
                self.http, "GET", f"{log}/proofs/inclusion",
                params={"index": event.anchor.index, "tree_size": sth.tree_size}).json())
            if not merkle.verify_inclusion(bytes.fromhex(event.anchor.leaf_hash), event.anchor.index,
                                           sth.tree_size, [bytes.fromhex(p) for p in proof.path], root):
                raise IntegrityViolation(f"event {event.sequence} is not included in the log")
            verified += 1

        consistent = None
        try:
            previous = self.ctx.store.get("tree_heads", "latest", SignedTreeHead)
        except NotFound:
            previous = None
        if previous and previous.tree_size <= sth.tree_size:
            proof = ConsistencyProof.model_validate(call(
                self.http, "GET", f"{log}/proofs/consistency",
                params={"first": previous.tree_size, "second": sth.tree_size}).json())
            consistent = merkle.verify_consistency(
                previous.tree_size, sth.tree_size, bytes.fromhex(previous.root_hash), root,
                [bytes.fromhex(p) for p in proof.path])
            if not consistent:
                raise IntegrityViolation("transparency log history was rewritten (inconsistent tree heads)")
        self.ctx.store.put("tree_heads", "latest", sth)
        return AuditReport(events=len(events), anchored=len(anchored), verified_inclusions=verified,
                           tree_size=sth.tree_size, root_hash=sth.root_hash,
                           consistent_with_previous=consistent)


def attestation_header(attestation: DataAttestation) -> str:
    return base64.urlsafe_b64encode(json.dumps(attestation.model_dump(mode="json")).encode()).decode()
