"""Error taxonomy shared by every service.

Each error carries an HTTP status. Services serialise errors as RFC 9457
problem documents; clients re-raise the same error class on their side, so
a policy violation detected by a provider surfaces as ``PolicyViolation`` in
the consumer's code.
"""

from __future__ import annotations


class DataSpaceError(Exception):
    status = 400

    def __init__(self, detail: str = ""):
        super().__init__(detail)
        self.detail = detail


class NotFound(DataSpaceError):
    status = 404


class Conflict(DataSpaceError):
    status = 409


class Unauthenticated(DataSpaceError):
    """The caller could not prove its identity (bad signature, unknown DID...)."""

    status = 401


class Forbidden(DataSpaceError):
    """The caller is identified but not allowed to perform the operation."""

    status = 403


class PolicyViolation(Forbidden):
    """A usage policy denies the requested action."""


class IntegrityViolation(DataSpaceError):
    """Data, signatures or logs do not match what was committed to."""

    status = 422


class ProtocolError(DataSpaceError):
    """A message is malformed or arrives in an invalid state."""


class UpstreamError(DataSpaceError):
    """A remote service is unreachable or answered unexpectedly."""

    status = 502


ERRORS: dict[str, type[DataSpaceError]] = {
    cls.__name__: cls
    for cls in (
        DataSpaceError, NotFound, Conflict, Unauthenticated, Forbidden,
        PolicyViolation, IntegrityViolation, ProtocolError, UpstreamError,
    )
}
