"""REST API of the data space.

Run with: ``uvicorn api.main:app --reload``
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.routes import access, datasets, participants, policies
from dataspace import DataSpace, __version__
from dataspace.core.config import load_participant_configs
from dataspace.core.exceptions import (
    AlreadyExistsError,
    AuthenticationError,
    AuthorizationError,
    DataSpaceError,
    IntegrityError,
    NotFoundError,
)

_STATUS = [
    (NotFoundError, 404),
    (AlreadyExistsError, 409),
    (AuthenticationError, 401),
    (AuthorizationError, 403),  # includes PolicyViolationError
    (IntegrityError, 422),
    (DataSpaceError, 400),
]


def create_app(space: DataSpace | None = None) -> FastAPI:
    app = FastAPI(title="Trustworthy Data Space", version=__version__)
    app.state.space = space or DataSpace()

    @app.exception_handler(DataSpaceError)
    async def handle_dataspace_error(request: Request, exc: DataSpaceError):
        status = next(code for cls, code in _STATUS if isinstance(exc, cls))
        return JSONResponse(status_code=status, content={"error": type(exc).__name__, "detail": str(exc)})

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    for module in (participants, datasets, policies, access):
        app.include_router(module.router)
    return app


def _default_space() -> DataSpace | None:
    """Seed from participant configs when ``DATASPACE_PARTICIPANTS_DIR`` is set."""
    root = os.environ.get("DATASPACE_PARTICIPANTS_DIR")
    if not root:
        return None
    space, _ = DataSpace.from_configs(load_participant_configs(root))
    return space


app = create_app(_default_space())
