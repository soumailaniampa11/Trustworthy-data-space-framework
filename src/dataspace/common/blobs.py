"""Object storage for dataset contents (data plane).

``storage_from_url`` selects the back end:

* ``memory://``                                   in-process (tests)
* ``file:///var/lib/dataspace``                   local directory
* ``minio://user:password@host:9000/bucket``      MinIO / S3-compatible
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlparse

from dataspace.common.errors import NotFound


class BlobStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...


class MemoryBlobStore:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put(self, key: str, data: bytes) -> None:
        self._blobs[key] = data

    def get(self, key: str) -> bytes:
        try:
            return self._blobs[key]
        except KeyError:
            raise NotFound(f"blob '{key}' not found") from None


class FileBlobStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError(f"invalid blob key '{key}'")
        return path

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not path.exists():
            raise NotFound(f"blob '{key}' not found")
        return path.read_bytes()


class MinioBlobStore:
    def __init__(self, endpoint: str, access_key: str, secret_key: str, bucket: str, secure: bool = False):
        from minio import Minio

        self._client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        self._bucket = bucket
        if not self._client.bucket_exists(bucket):
            self._client.make_bucket(bucket)

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(self._bucket, key, io.BytesIO(data), length=len(data))

    def get(self, key: str) -> bytes:
        from minio.error import S3Error

        try:
            response = self._client.get_object(self._bucket, key)
        except S3Error as exc:
            if exc.code == "NoSuchKey":
                raise NotFound(f"blob '{key}' not found") from None
            raise
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()


def storage_from_url(url: str) -> BlobStore:
    parsed = urlparse(url)
    if parsed.scheme == "memory":
        return MemoryBlobStore()
    if parsed.scheme == "file":
        return FileBlobStore(unquote(parsed.path))
    if parsed.scheme in ("minio", "minios"):
        return MinioBlobStore(
            endpoint=f"{parsed.hostname}:{parsed.port or 9000}",
            access_key=unquote(parsed.username or ""),
            secret_key=unquote(parsed.password or ""),
            bucket=parsed.path.strip("/"),
            secure=parsed.scheme == "minios",
        )
    raise ValueError(f"unsupported storage url '{url}'")
