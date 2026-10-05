"""Connector configuration: deployment settings (environment) and participant profile (YAML)."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from dataspace.policy.model import Rule


class DatasetSpec(BaseModel):
    """A dataset published by the connector at start-up."""

    id: str
    title: str
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    media_type: str = "text/csv"
    sensitivity: str = "internal"
    license: str | None = None
    source: str
    """Path of the content, relative to the participant directory."""
    rules: list[Rule] = Field(default_factory=list)


class ParticipantProfile(BaseModel):
    name: str
    organization: str
    endpoint: str
    """Public URL of the participant's connector (defines its did:web)."""
    datasets: list[DatasetSpec] = Field(default_factory=list)
    base_dir: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> ParticipantProfile:
        path = Path(path)
        data = yaml.safe_load(path.read_text()) or {}
        profile = cls.model_validate(data.get("participant", data))
        profile.base_dir = path.parent.parent  # <participant>/config/participant.yaml
        return profile


class ConnectorSettings(BaseModel):
    public_url: str
    authority_url: str
    catalog_url: str
    transparency_url: str
    management_api_key: str
    database_url: str = "sqlite://"
    storage_url: str = "memory://"
    key_file: str | None = None
    did_scheme: str = "https"
    trusted_issuers: list[str] | None = None
    """DIDs whose credentials are accepted (default: the authority)."""
    agreement_validity: timedelta = timedelta(days=30)
    data_address_ttl: timedelta = timedelta(minutes=5)
    profile: ParticipantProfile | None = None

    @classmethod
    def from_env(cls) -> ConnectorSettings:
        profile = ParticipantProfile.load(os.environ["PARTICIPANT_CONFIG"]) \
            if os.environ.get("PARTICIPANT_CONFIG") else None
        public_url = os.environ.get("PUBLIC_URL") or (profile.endpoint if profile else None)
        issuers = os.environ.get("TRUSTED_ISSUERS")
        return cls(
            public_url=public_url,
            authority_url=os.environ["AUTHORITY_URL"],
            catalog_url=os.environ["CATALOG_URL"],
            transparency_url=os.environ["TRANSPARENCY_URL"],
            management_api_key=os.environ["MANAGEMENT_API_KEY"],
            database_url=os.environ.get("DATABASE_URL", "sqlite://"),
            storage_url=os.environ.get("STORAGE_URL", "memory://"),
            key_file=os.environ.get("KEY_FILE"),
            did_scheme=os.environ.get("DID_SCHEME", "https"),
            trusted_issuers=issuers.split(",") if issuers else None,
            profile=profile,
        )
