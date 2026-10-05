"""``DataSpace``: wires all components together behind one entry point."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Iterable

from dataspace.access.authorization import AuthorizationService
from dataspace.access.request import AccessRequest
from dataspace.audit.logger import AuditLogger
from dataspace.catalog.catalog import Catalog
from dataspace.catalog.dataset import Dataset, sha256
from dataspace.catalog.metadata import DatasetMetadata
from dataspace.core.config import ParticipantConfig, Settings
from dataspace.core.exceptions import AuthorizationError
from dataspace.exchange.connector import Connector
from dataspace.exchange.transfer import TransferProcess, TransferService
from dataspace.identity.authentication import IdentityProvider
from dataspace.identity.participant import KeyPair, Participant, ParticipantRegistry, Role
from dataspace.policy.policy import Action, Policy, PolicyStore, Rule


class DataSpace:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.audit = AuditLogger(self.settings.audit_log_path)
        self.registry = ParticipantRegistry()
        self.identity = IdentityProvider(
            self.registry,
            token_ttl=timedelta(seconds=self.settings.token_ttl_seconds),
            challenge_ttl=timedelta(seconds=self.settings.challenge_ttl_seconds),
        )
        self.catalog = Catalog()
        self.policies = PolicyStore()
        self.connectors: dict[str, Connector] = {}
        self.authz = AuthorizationService(
            self.catalog,
            self.policies,
            self.audit,
            default_grant_ttl=timedelta(seconds=self.settings.default_grant_ttl_seconds),
        )
        self.transfers = TransferService(
            self.registry, self.catalog, self.authz, self.audit, self.connectors
        )

    # -- participants --------------------------------------------------------

    def register(
        self,
        participant_id: str,
        name: str,
        organization: str,
        public_key: str,
        roles: Iterable[Role | str] = (Role.CONSUMER,),
        attributes: dict[str, Any] | None = None,
    ) -> Participant:
        """Register a participant whose identity key is held externally."""
        connector = Connector(participant_id)
        participant = Participant(
            id=participant_id,
            name=name,
            organization=organization,
            public_key=public_key,
            connector_key=connector.public_key,
            roles={Role(r) for r in roles},
            attributes=attributes or {},
        )
        self.registry.register(participant)
        self.connectors[participant_id] = connector
        self.audit.log(participant_id, "participant.registered", participant_id,
                       roles=sorted(r.value for r in participant.roles))
        return participant

    def join(
        self,
        participant_id: str,
        name: str,
        organization: str,
        roles: Iterable[Role | str] = (Role.CONSUMER,),
        attributes: dict[str, Any] | None = None,
    ) -> tuple[Participant, KeyPair]:
        """Create a key pair and register a participant (simulation helper)."""
        keys = KeyPair()
        participant = self.register(
            participant_id, name, organization, keys.public_key, roles, attributes
        )
        return participant, keys

    def login(self, participant_id: str, keys: KeyPair) -> str:
        """Run the challenge-response flow and return a session token."""
        challenge = self.identity.create_challenge(participant_id)
        return self.identity.authenticate(participant_id, keys.sign(challenge.encode()))

    # -- datasets and policies ----------------------------------------------

    def publish_dataset(
        self,
        owner_id: str,
        dataset_id: str,
        data: bytes,
        metadata: DatasetMetadata,
        rules: list[Rule] | None = None,
    ) -> Dataset:
        owner = self.registry.get(owner_id)
        if not owner.has_role(Role.PROVIDER):
            raise AuthorizationError("participant does not hold the provider role")
        checksum = self.connectors[owner_id].store(dataset_id, data)
        dataset = self.catalog.publish(
            Dataset(id=dataset_id, owner_id=owner_id, metadata=metadata,
                    checksum=checksum, size=len(data))
        )
        self.audit.log(owner_id, "dataset.published", dataset_id, checksum=checksum)
        if rules is not None:
            self.set_policy(owner_id, dataset_id, rules)
        return dataset

    def set_policy(self, owner_id: str, dataset_id: str, rules: list[Rule]) -> Policy:
        """Attach a new policy (or a new version of it) to a dataset."""
        dataset = self.catalog.get(dataset_id)
        if dataset.owner_id != owner_id:
            raise AuthorizationError("only the owner can set a dataset's policy")
        version = 1
        if dataset.policy_id:
            version = self.policies.get(dataset.policy_id).version + 1
        policy = self.policies.add(
            Policy(id=f"policy-{dataset_id}-v{version}", assigner=owner_id,
                   target=dataset_id, rules=rules, version=version)
        )
        self.catalog.attach_policy(dataset_id, policy.id, owner_id)
        self.audit.log(owner_id, "policy.set", dataset_id, policy_id=policy.id, version=version)
        return policy

    def withdraw_dataset(self, owner_id: str, dataset_id: str) -> Dataset:
        dataset = self.catalog.withdraw(dataset_id, owner_id)
        self.audit.log(owner_id, "dataset.withdrawn", dataset_id)
        return dataset

    # -- access and exchange -------------------------------------------------

    def request_access(
        self,
        participant_id: str,
        dataset_id: str,
        action: Action | str,
        purpose: str | None = None,
        max_uses: int | None = None,
    ) -> AccessRequest:
        participant = self.registry.get(participant_id)
        return self.authz.request_access(participant, dataset_id, Action(action), purpose, max_uses)

    def transfer(self, grant_id: str, consumer_id: str) -> tuple[TransferProcess, bytes]:
        process = self.transfers.transfer(grant_id, self.registry.get(consumer_id))
        return process, self.connectors[consumer_id].received(process.id)

    # -- bootstrap -----------------------------------------------------------

    @classmethod
    def from_configs(
        cls, configs: Iterable[ParticipantConfig], settings: Settings | None = None
    ) -> tuple[DataSpace, dict[str, KeyPair]]:
        space = cls(settings)
        keys: dict[str, KeyPair] = {}
        configs = list(configs)
        for cfg in configs:
            _, keys[cfg.id] = space.join(cfg.id, cfg.name, cfg.organization, cfg.roles, cfg.attributes)
        for cfg in configs:
            for ds in cfg.datasets:
                data = b""
                if ds.source:
                    source = (cfg.base_dir / ds.source) if cfg.base_dir else None
                    if source and source.exists():
                        data = source.read_bytes()
                space.publish_dataset(
                    cfg.id,
                    ds.id,
                    data,
                    DatasetMetadata(
                        title=ds.title, description=ds.description, keywords=ds.keywords,
                        format=ds.format, sensitivity=ds.sensitivity, license=ds.license,
                    ),
                    ds.rules,
                )
        return space, keys


__all__ = ["DataSpace", "sha256"]
