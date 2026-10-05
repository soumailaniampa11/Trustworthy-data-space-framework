"""Dataset offers (DCAT 3 dataset description + ODRL offer), signed by the provider."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from dataspace.identity.proofs import Signed


class DatasetOffer(Signed):
    id: str
    title: str
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    media_type: str = "application/octet-stream"
    sensitivity: str = "internal"
    license: str | None = None
    byte_size: int
    checksum: str
    """SHA-256 of the content: consumers verify received data against it."""
    provider: str
    """DID of the provider."""
    endpoint: str
    """Protocol endpoint of the provider's connector."""
    policy: dict[str, Any]
    """ODRL 2.2 offer governing the dataset."""
    issued: datetime
    withdrawn: bool = False

    @property
    def key(self) -> str:
        return f"{self.provider}|{self.id}"

    def to_dcat(self) -> dict[str, Any]:
        """JSON-LD view of the offer using the DCAT 3 vocabulary."""
        return {
            "@context": {"dcat": "http://www.w3.org/ns/dcat#", "dct": "http://purl.org/dc/terms/",
                         "odrl": "http://www.w3.org/ns/odrl/2/"},
            "@id": self.id,
            "@type": "dcat:Dataset",
            "dct:title": self.title,
            "dct:description": self.description,
            "dcat:keyword": self.keywords,
            "dct:publisher": self.provider,
            "dct:license": self.license,
            "dct:issued": self.issued.isoformat(),
            "odrl:hasPolicy": self.policy,
            "dcat:distribution": {
                "@type": "dcat:Distribution",
                "dcat:mediaType": self.media_type,
                "dcat:byteSize": self.byte_size,
                "spdx:checksum": {"spdx:algorithm": "sha256", "spdx:checksumValue": self.checksum},
                "dcat:accessService": self.endpoint,
            },
        }
