"""Descriptive metadata attached to every dataset in the catalog."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class DatasetMetadata(BaseModel):
    title: str
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    format: str = "application/octet-stream"
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    license: str | None = None

    def matches(self, text: str) -> bool:
        text = text.lower()
        return (
            text in self.title.lower()
            or text in self.description.lower()
            or any(text in k.lower() for k in self.keywords)
        )
