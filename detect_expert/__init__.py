"""
Detect Expert DNS Check Client

A Python client for detect.expert DNS checking service.
Bypasses Cloudflare protection using TLS fingerprinting.
"""

from .client import DetectExpertClient
from .models import DNSRecord, CheckResult
from .exceptions import (
    DetectExpertError,
    AuthenticationError,
    InsufficientFundsError,
    CheckError,
)

__version__ = "1.0.0"
__all__ = [
    "DetectExpertClient",
    "DNSRecord",
    "CheckResult",
    "DetectExpertError",
    "AuthenticationError",
    "InsufficientFundsError",
    "CheckError",
]
