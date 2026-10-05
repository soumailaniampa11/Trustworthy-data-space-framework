"""Configuration models, loaded from participant YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from dataspace.policy.policy import Rule


class DatasetConfig(BaseModel):
    """A dataset a participant publishes at start-up."""

    id: str
    title: str
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    format: str = "text/csv"
    sensitivity: str = "internal"
    license: str | None = None
    source: str | None = None
    """Path to the data file, relative to the participant directory."""
    rules: list[Rule] = Field(default_factory=list)


class ParticipantConfig(BaseModel):
    id: str
    name: str
    organization: str
    roles: list[str] = Field(default_factory=lambda: ["consumer"])
    attributes: dict[str, Any] = Field(default_factory=dict)
    datasets: list[DatasetConfig] = Field(default_factory=list)
    base_dir: Path | None = None


class Settings(BaseModel):
    """Data-space-wide settings."""

    token_ttl_seconds: int = 3600
    challenge_ttl_seconds: int = 120
    default_grant_ttl_seconds: int = 86400
    audit_log_path: Path | None = None


def load_participant_config(path: str | Path) -> ParticipantConfig:
    path = Path(path)
    data = yaml.safe_load(path.read_text()) or {}
    config = ParticipantConfig.model_validate(data.get("participant", data))
    # participants/<name>/config/participant.yaml -> participants/<name>
    config.base_dir = path.parent.parent
    return config


def load_participant_configs(root: str | Path) -> list[ParticipantConfig]:
    """Load every ``*/config/participant.yaml`` under ``root``."""
    return [load_participant_config(p) for p in sorted(Path(root).glob("*/config/participant.yaml"))]
