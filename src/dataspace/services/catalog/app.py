"""Federated catalog: an index of signed dataset offers.

The catalog stores offers, never data. It only accepts offers signed by
the provider's DID whose endpoint matches the provider's DID document, and
consumers re-verify every offer themselves: the catalog is a convenience,
not a trusted party.

Run: uvicorn --factory dataspace.services.catalog.app:create_app_from_env
"""

from __future__ import annotations

from dataspace.common.errors import Conflict, NotFound, Unauthenticated
from dataspace.protocol.catalog import DatasetOffer
from dataspace.services.base import ServiceContext, context_from_env, service_app


def create_app(ctx: ServiceContext):
    app = service_app("Federated Catalog", "Index of signed DCAT/ODRL dataset offers.", ctx)

    def current(key: str) -> DatasetOffer | None:
        try:
            return ctx.store.get("offers", key, DatasetOffer)
        except NotFound:
            return None

    @app.post("/offers", response_model=DatasetOffer, status_code=201, tags=["catalog"])
    def publish(offer: DatasetOffer) -> DatasetOffer:
        ctx.resolver.verify(offer, expected_signer=offer.provider)
        declared = ctx.resolver.resolve(offer.provider).endpoint("DataSpaceProtocol")
        if declared != offer.endpoint:
            raise Unauthenticated("offer endpoint does not match the provider's DID document")
        previous = current(offer.key)
        if previous and previous.issued >= offer.issued:
            raise Conflict("a newer version of this offer is already published")
        ctx.store.put("offers", offer.key, offer)
        return offer

    @app.get("/offers", response_model=list[DatasetOffer], tags=["catalog"])
    def search(q: str | None = None, provider: str | None = None,
               sensitivity: str | None = None) -> list[DatasetOffer]:
        offers = [o for o in ctx.store.find("offers", DatasetOffer) if not o.withdrawn]
        if q:
            needle = q.lower()
            offers = [o for o in offers if needle in " ".join([o.id, o.title, o.description, *o.keywords]).lower()]
        if provider:
            offers = [o for o in offers if o.provider == provider]
        if sensitivity:
            offers = [o for o in offers if o.sensitivity == sensitivity]
        return offers

    @app.get("/offers/item", response_model=DatasetOffer, tags=["catalog"])
    def get_offer(provider: str, id: str) -> DatasetOffer:
        offer = current(f"{provider}|{id}")
        if offer is None or offer.withdrawn:
            raise NotFound(f"offer '{id}' of {provider} not found")
        return offer

    @app.get("/offers/item/dcat", tags=["catalog"])
    def get_offer_dcat(provider: str, id: str) -> dict:
        """The offer as a DCAT 3 JSON-LD dataset."""
        return get_offer(provider, id).to_dcat()

    return app


def create_app_from_env():
    return create_app(context_from_env())
