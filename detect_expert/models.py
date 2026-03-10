"""Data models for Detect Expert client."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class DNSRecord:
    """A single DNS record from check results.

    Attributes:
        ip: IP address of the DNS resolver.
        provider: ISP or hosting provider name.
        country: Country where the resolver is located.
        region: Region/state code.
        city: City name.
    """

    ip: str
    provider: str = ""
    country: str = ""
    region: str = ""
    city: str = ""

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CheckResult:
    """DNS check result containing all discovered resolver records.

    Attributes:
        check_id: Unique identifier of the check on detect.expert.
        session_id: Session identifier for result pagination.
        ip_checked: The IP address that was checked.
        records: List of discovered DNS resolver records.
        created_at: Timestamp when the check was created.
    """

    check_id: str
    session_id: str
    ip_checked: str
    records: list[DNSRecord] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    @property
    def url(self) -> str:
        """Get the URL for this check result on detect.expert."""
        return f"https://detect.expert/dnscheck/{self.check_id}/{self.session_id}"

    @property
    def total_records(self) -> int:
        """Get total number of DNS records."""
        return len(self.records)

    @property
    def unique_ips(self) -> list[str]:
        """Get list of unique IP addresses."""
        return list({r.ip for r in self.records})

    @property
    def providers(self) -> dict[str, int]:
        """Get provider statistics sorted by count descending."""
        stats: dict[str, int] = {}
        for record in self.records:
            provider = record.provider or "Unknown"
            stats[provider] = stats.get(provider, 0) + 1
        return dict(sorted(stats.items(), key=lambda x: -x[1]))

    def to_dict(self) -> dict[str, object]:
        """Convert to serializable dictionary."""
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

    def to_ip_list(self) -> list[str]:
        """Get list of all IP addresses."""
        return [r.ip for r in self.records]


@dataclass
class AccountInfo:
    """Account information.

    Attributes:
        email: Account email address.
        balance: Current account balance in USD.
        is_authenticated: Whether the client is authenticated.
    """

    email: str
    balance: float | None = None
    is_authenticated: bool = False
