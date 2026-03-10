"""
Detect Expert DNS Check Client.

A Python client for detect.expert DNS checking service.
Bypasses Cloudflare protection using TLS fingerprinting.
"""

from .client import DetectExpertClient
from .exceptions import (
    AuthenticationError,
    CheckError,
    DetectExpertError,
    InsufficientFundsError,
    RateLimitError,
)
from .models import AccountInfo, CheckResult, DNSRecord

__version__ = "1.0.0"
__all__ = [
    "DetectExpertClient",
    "DNSRecord",
    "CheckResult",
    "AccountInfo",
    "DetectExpertError",
    "AuthenticationError",
    "InsufficientFundsError",
    "CheckError",
    "RateLimitError",
]
