"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dataspace import DataSpace
from dataspace.core.exceptions import AuthenticationError
from dataspace.identity.participant import Participant

_bearer = HTTPBearer(auto_error=False)


def get_space(request: Request) -> DataSpace:
    return request.app.state.space


def current_participant(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    space: DataSpace = Depends(get_space),
) -> Participant:
    if credentials is None:
        raise AuthenticationError("missing bearer token")
    return space.identity.verify_token(credentials.credentials)
