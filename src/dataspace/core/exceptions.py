"""Exception hierarchy for the data space framework."""


class DataSpaceError(Exception):
    """Base class for all framework errors."""


class NotFoundError(DataSpaceError):
    """A referenced participant, dataset, policy or grant does not exist."""


class AlreadyExistsError(DataSpaceError):
    """An entity with the same identifier is already registered."""


class AuthenticationError(DataSpaceError):
    """The caller could not prove its identity (bad signature, expired token...)."""


class AuthorizationError(DataSpaceError):
    """The caller is authenticated but not allowed to perform the operation."""


class PolicyViolationError(AuthorizationError):
    """A usage policy denies the requested action."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class IntegrityError(DataSpaceError):
    """Data or audit records were tampered with (checksum or hash-chain mismatch)."""


class TransferError(DataSpaceError):
    """A data transfer between connectors failed."""
