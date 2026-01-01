"""
Detect Expert DNS Check Client.

This client bypasses Cloudflare protection using TLS fingerprinting
via the tls-client library.
"""

import re
import json
import time
import logging
from typing import Optional, List, Iterator, Callable

try:
    import tls_client
except ImportError:
    raise ImportError(
        "tls-client is required. Install it with: pip install tls-client"
    )

from .models import DNSRecord, CheckResult, AccountInfo
from .exceptions import (
    AuthenticationError,
    InsufficientFundsError,
    CheckError,
    RateLimitError,
)

logger = logging.getLogger(__name__)


class DetectExpertClient:
    """
    Client for detect.expert DNS checking service.

    This client uses TLS fingerprinting to bypass Cloudflare protection,
    allowing automated DNS checks without a browser.

    Example:
        >>> client = DetectExpertClient()
        >>> client.login("user@example.com", "password")
        >>> result = client.check_dns("8.8.8.8")
        >>> for record in result.records:
        ...     print(record.ip, record.provider)
    """

    BASE_URL = "https://detect.expert"
    DEFAULT_BROWSER = "chrome_131"
    CHECK_PRICE = 0.15

    def __init__(
        self,
        browser: str = DEFAULT_BROWSER,
        timeout: int = 30,
    ):
        """
        Initialize the client.

        Args:
            browser: Browser to impersonate (default: chrome_131)
            timeout: Request timeout in seconds
        """
        self._session = tls_client.Session(
            client_identifier=browser,
            random_tls_extension_order=True,
        )
        self._timeout = timeout
        self._account = AccountInfo(email="")

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._account.is_authenticated

    @property
    def balance(self) -> Optional[float]:
        """Get current account balance."""
        return self._account.balance

    def login(self, email: str, password: str) -> AccountInfo:
        """
        Authenticate with detect.expert.

        Args:
            email: Account email
            password: Account password

        Returns:
            AccountInfo with authentication status and balance

        Raises:
            AuthenticationError: If login fails
        """
        logger.info(f"Authenticating as {email}")

        # Get CSRF token
        resp = self._session.get(
            f"{self.BASE_URL}/oauth/login/",
            timeout_seconds=self._timeout,
        )

        if resp.status_code != 200:
            raise AuthenticationError("Failed to load login page")

        csrf_match = re.search(
            r'name="csrfmiddlewaretoken"[^>]*value="([^"]+)"',
            resp.text,
        )
        if not csrf_match:
            raise AuthenticationError("CSRF token not found")

        # Submit login
        resp = self._session.post(
            f"{self.BASE_URL}/oauth/login/",
            data={
                "csrfmiddlewaretoken": csrf_match.group(1),
                "login": email,
                "password": password,
            },
            headers={
                "Referer": f"{self.BASE_URL}/oauth/login/",
                "Origin": self.BASE_URL,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            allow_redirects=True,
            timeout_seconds=self._timeout,
        )

        if "/oauth/login/" in resp.url:
            raise AuthenticationError("Invalid email or password")

        self._account.email = email
        self._account.is_authenticated = True

        # Get balance
        self._update_balance()

        logger.info(f"Authenticated successfully. Balance: ${self._account.balance}")
        return self._account

    def _update_balance(self) -> None:
        """Update account balance from server."""
        resp = self._session.get(
            f"{self.BASE_URL}/dnscheck/check/",
            timeout_seconds=self._timeout,
        )

        balance_match = re.search(r'balance">\$([0-9.]+)', resp.text)
        if balance_match:
            self._account.balance = float(balance_match.group(1))

    def _get_csrf_token(self) -> str:
        """Get CSRF token from cookies."""
        token = self._session.cookies.get("csrftoken")
        if not token:
            raise CheckError("CSRF token not found in cookies")
        return token

    def check_dns(
        self,
        ip_address: str,
        wait_seconds: float = 3.0,
        fetch_results: bool = True,
        max_pages: int = 300,
        page_delay: float = 0.2,
    ) -> CheckResult:
        """
        Run DNS check for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address to check
            wait_seconds: Seconds to wait after starting check
            fetch_results: Whether to fetch results immediately
            max_pages: Maximum pages to fetch
            page_delay: Delay between page requests

        Returns:
            CheckResult with DNS records

        Raises:
            AuthenticationError: If not authenticated
            InsufficientFundsError: If balance is too low
            CheckError: If check fails
        """
        if not self.is_authenticated:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.info(f"Starting DNS check for {ip_address}")

        csrf_token = self._get_csrf_token()

        resp = self._session.post(
            f"{self.BASE_URL}/dnscheck/check/",
            data={
                "value": ip_address,
                "is_expert_check": "1",
            },
            headers={
                "X-CSRFToken": csrf_token,
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{self.BASE_URL}/dnscheck/check/",
                "Origin": self.BASE_URL,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout_seconds=self._timeout,
        )

        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise CheckError("Invalid server response")

        if data.get("status") == "error":
            code = data.get("code", "")
            message = data.get("message", "Unknown error")

            if code == "insufficient_funds":
                raise InsufficientFundsError(
                    f"Insufficient funds. Balance: ${self.balance}, "
                    f"Required: ${self.CHECK_PRICE}"
                )
            raise CheckError(message)

        if data.get("status") != "ok":
            raise CheckError("Check failed with unknown error")

        redirect = data.get("redirect_to", "")
        match = re.search(r"/dnscheck/([^/]+)/([^/?]+)", redirect)

        if not match:
            raise CheckError("Failed to parse check result URL")

        check_id = match.group(1)
        session_id = match.group(2)

        logger.info(f"Check started: {check_id}")

        result = CheckResult(
            check_id=check_id,
            session_id=session_id,
            ip_checked=ip_address,
        )

        # Update balance
        self._update_balance()

        if fetch_results:
            if wait_seconds > 0:
                logger.debug(f"Waiting {wait_seconds}s for results...")
                time.sleep(wait_seconds)

            result.records = list(
                self.fetch_results(
                    check_id,
                    session_id,
                    max_pages=max_pages,
                    delay=page_delay,
                )
            )

        return result

    def fetch_results(
        self,
        check_id: str,
        session_id: str,
        max_pages: int = 300,
        delay: float = 0.2,
        retry_delay: float = 2.0,
        max_retries: int = 10,
        on_page: Optional[Callable[[int, int], None]] = None,
    ) -> Iterator[DNSRecord]:
        """
        Fetch DNS check results page by page.

        Args:
            check_id: Check ID
            session_id: Session ID
            max_pages: Maximum pages to fetch
            delay: Delay between requests in seconds
            retry_delay: Delay before retrying pages with 'retry' status
            max_retries: Maximum retries for 'retry' status pages
            on_page: Callback(page_num, total_records) for progress

        Yields:
            DNSRecord objects
        """
        empty_count = 0
        total_records = 0
        retry_count = 0

        for page in range(1, max_pages + 1):
            records, status = self._fetch_page(check_id, session_id, page)

            # Handle retry status - check is still in progress
            if status == "retry":
                if retry_count < max_retries:
                    retry_count += 1
                    time.sleep(retry_delay)
                    records, status = self._fetch_page(check_id, session_id, page)

            if not records:
                empty_count += 1
                if empty_count >= 3:
                    break
                continue

            empty_count = 0
            retry_count = 0  # Reset retry count on success
            total_records += len(records)

            if on_page:
                on_page(page, total_records)

            yield from records

            if delay > 0 and page < max_pages:
                time.sleep(delay)

    def _fetch_page(
        self,
        check_id: str,
        session_id: str,
        page: int,
    ) -> tuple[List[DNSRecord], str]:
        """Fetch a single page of results.

        Returns:
            Tuple of (records, status) where status is 'ok', 'retry', or 'error'
        """
        url = f"{self.BASE_URL}/dnscheck/{check_id}/{session_id}?page={page}"

        resp = self._session.get(
            url,
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
            timeout_seconds=self._timeout,
        )


        if resp.status_code == 429:
            raise RateLimitError("Rate limit exceeded")

        if resp.status_code != 200:
            return [], "error"

        try:
            data = resp.json()
        except json.JSONDecodeError:
            return [], "error"

        status = data.get("status", "error")
        if status == "retry":
            return [], "retry"
        if status != "ok":
            return [], status

        records = self._parse_results_html(data.get("html", ""))
        return records, "ok"

    def _parse_results_html(self, html: str) -> List[DNSRecord]:
        """Parse DNS records from HTML response."""
        records = []

        # Desktop format: num, IP, provider, country, region (link), city (link)
        # Region and city are <a> tags, not <p>
        pattern = (
            r'd-none d-md-flex justify-content-between gap-24 b4">\s*'
            r'<p>(\d+)</p>\s*'
            r'<p class="flex-1">([^<]+)</p>\s*'
            r'<p class="flex-2">([^<]+)</p>\s*'
            r'<p class="flex-1">([^<]+)</p>\s*'
            r'<a[^>]*class="[^"]*flex-1"[^>]*>\s*([^<]*)\s*</a>\s*'
            r'<a[^>]*class="[^"]*flex-1"[^>]*>\s*([^<]*)\s*</a>'
        )

        for match in re.finditer(pattern, html):
            records.append(
                DNSRecord(
                    ip=match.group(2).strip(),
                    provider=match.group(3).strip(),
                    country=match.group(4).strip(),
                    region=match.group(5).strip(),
                    city=match.group(6).strip(),
                )
            )

        # Fallback: extract IPs only
        if not records:
            ips = re.findall(r'js-mydns-ipaddress">([^<]+)</p>', html)
            for ip in ips:
                records.append(DNSRecord(ip=ip.strip()))

        return records

    def get_history(self, limit: int = 10) -> List[dict]:
        """
        Get check history.

        Args:
            limit: Maximum number of results

        Returns:
            List of check info dicts with check_id and session_id
        """
        if not self.is_authenticated:
            raise AuthenticationError("Not authenticated")

        resp = self._session.get(
            f"{self.BASE_URL}/dnscheck/history/",
            timeout_seconds=self._timeout,
        )

        checks = []
        pattern = r"/dnscheck/([a-f0-9]+)/([a-f0-9]+)"

        for match in re.finditer(pattern, resp.text):
            check_info = {
                "check_id": match.group(1),
                "session_id": match.group(2),
            }
            if check_info not in checks:
                checks.append(check_info)
                if len(checks) >= limit:
                    break

        return checks
