"""Data models for Detect Expert client."""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime


@dataclass
class DNSRecord:
    """Represents a single DNS record from check results."""

    ip: str
    provider: str = ""
    country: str = ""
    region: str = ""
    city: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CheckResult:
    """Represents a DNS check result."""

    check_id: str
    session_id: str
    ip_checked: str
    records: List[DNSRecord] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def url(self) -> str:
        """Get the URL for this check result."""
        return f"https://detect.expert/dnscheck/{self.check_id}/{self.session_id}"

    @property
    def total_records(self) -> int:
        """Get total number of DNS records."""
        return len(self.records)

    @property
    def unique_ips(self) -> List[str]:
        """Get list of unique IP addresses."""
        return list(set(r.ip for r in self.records))

    @property
    def providers(self) -> dict:
        """Get provider statistics."""
        stats = {}
        for record in self.records:
            provider = record.provider or "Unknown"
            stats[provider] = stats.get(provider, 0) + 1
        return dict(sorted(stats.items(), key=lambda x: -x[1]))

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "check_id": self.check_id,
            "session_id": self.session_id,
            "ip_checked": self.ip_checked,
            "url": self.url,
            "total_records": self.total_records,
            "records": [r.to_dict() for r in self.records],
            "providers": self.providers,
            "created_at": self.created_at.isoformat(),
        }

    def to_ip_list(self) -> List[str]:
        """Get list of all IP addresses."""
        return [r.ip for r in self.records]


@dataclass
class AccountInfo:
    """Account information."""

    email: str
    balance: Optional[float] = None
    is_authenticated: bool = False
