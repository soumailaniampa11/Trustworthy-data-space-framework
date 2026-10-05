"""HTTP plumbing shared by services: problem documents and error propagation."""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from dataspace.common.errors import ERRORS, DataSpaceError, UpstreamError


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DataSpaceError)
    async def _problem(request: Request, exc: DataSpaceError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status,
            media_type="application/problem+json",
            content={"type": type(exc).__name__, "title": type(exc).__name__,
                     "status": exc.status, "detail": exc.detail},
        )


def expect_json(response: httpx.Response) -> Any:
    """Return the JSON body, or re-raise the remote error locally."""
    raise_for_problem(response)
    return response.json()


def raise_for_problem(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        body = response.json()
        error = ERRORS.get(body.get("type", ""), DataSpaceError)
        detail = body.get("detail", "")
    except (ValueError, AttributeError):
        error, detail = UpstreamError, response.text[:200]
    raise error(detail)


def call(http: httpx.Client, method: str, url: str, **kwargs: Any) -> httpx.Response:
    try:
        response = http.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise UpstreamError(f"{method} {url}: {exc}") from exc
    raise_for_problem(response)
    return response
