"""Federated-style catalog of dataset offers."""

from __future__ import annotations

from dataspace.catalog.dataset import Dataset
from dataspace.catalog.metadata import Sensitivity
from dataspace.core.exceptions import AlreadyExistsError, AuthorizationError, NotFoundError


class Catalog:
    def __init__(self) -> None:
        self._datasets: dict[str, Dataset] = {}

    def publish(self, dataset: Dataset) -> Dataset:
        if dataset.id in self._datasets:
            raise AlreadyExistsError(f"dataset '{dataset.id}' already published")
        self._datasets[dataset.id] = dataset
        return dataset

    def get(self, dataset_id: str, include_withdrawn: bool = False) -> Dataset:
        dataset = self._datasets.get(dataset_id)
        if dataset is None or (dataset.withdrawn and not include_withdrawn):
            raise NotFoundError(f"dataset '{dataset_id}' not found")
        return dataset

    def withdraw(self, dataset_id: str, requester_id: str) -> Dataset:
        dataset = self.get(dataset_id)
        if dataset.owner_id != requester_id:
            raise AuthorizationError("only the owner can withdraw a dataset")
        dataset.withdrawn = True
        return dataset

    def attach_policy(self, dataset_id: str, policy_id: str, requester_id: str) -> Dataset:
        dataset = self.get(dataset_id)
        if dataset.owner_id != requester_id:
            raise AuthorizationError("only the owner can change a dataset's policy")
        dataset.policy_id = policy_id
        return dataset

    def search(
        self,
        text: str | None = None,
        owner_id: str | None = None,
        sensitivity: Sensitivity | None = None,
    ) -> list[Dataset]:
        results = [d for d in self._datasets.values() if not d.withdrawn]
        if text:
            results = [d for d in results if d.metadata.matches(text)]
        if owner_id:
            results = [d for d in results if d.owner_id == owner_id]
        if sensitivity:
            results = [d for d in results if d.metadata.sensitivity == sensitivity]
        return results
