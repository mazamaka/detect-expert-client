"""Custom exceptions for Detect Expert client."""


class DetectExpertError(Exception):
    """Base exception for all Detect Expert errors."""

    pass


class AuthenticationError(DetectExpertError):
    """Raised when authentication fails."""

    pass


class InsufficientFundsError(DetectExpertError):
    """Raised when account balance is insufficient."""

    pass


class CheckError(DetectExpertError):
    """Raised when DNS check fails."""

    pass


class RateLimitError(DetectExpertError):
    """Raised when rate limit is exceeded."""

    pass
