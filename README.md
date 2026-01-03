# Detect Expert DNS Check Client

[![PyPI](https://img.shields.io/pypi/v/detect-expert-client?color=blue)](https://pypi.org/project/detect-expert-client/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/docker/v/mazamaka/detect-expert-client?label=docker&color=blue)](https://hub.docker.com/r/mazamaka/detect-expert-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python client for [detect.expert](https://detect.expert) DNS checking service.

**Key feature:** Bypasses Cloudflare protection using TLS fingerprinting — no browser required!

> Works where `requests` and `httpx` fail — passes Cloudflare's bot detection by impersonating Chrome's TLS handshake.

## Features

- **Cloudflare Bypass** — Uses [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) to impersonate Chrome TLS fingerprint
- **Fast Pagination** — Fetches all pages with progress indicator and smart retry logic
- **Full Data** — Extracts IP, provider, country, region, and city
- **CLI Tool** — Command-line interface with real-time progress
- **Export** — JSON, CSV, or plain IP list

## Installation

```bash
pip install detect-expert-client
```

Or install from source:

```bash
git clone https://github.com/mazamaka/detect-expert-client.git
cd detect-expert-client
pip install -e .
```

## Docker

Pull and run with Docker — no Python installation needed:

```bash
# Pull latest image
docker pull mazamaka/detect-expert-client:latest

# Run DNS check
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p your_password \
  check 8.8.8.8

# Save results to local file
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p your_password \
  check 8.8.8.8 -o /data/results.json

# View check history
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p your_password \
  history
```

Build from source:

```bash
docker build -t detect-expert-client .
docker run --rm detect-expert-client --help
```

## Quick Start

### Set Credentials

```bash
export DETECT_EXPERT_EMAIL="your@email.com"
export DETECT_EXPERT_PASSWORD="your_password"
```

### Run New DNS Check (All Pages)

```bash
# Full check - fetches ALL pages automatically
detect-expert check 8.8.8.8 -o results.json

# With longer wait for large checks
detect-expert check 8.8.8.8 -o results.json --wait 10
```

### Fetch Only First Page (Quick Preview)

```bash
# Only first 100 records
detect-expert check 8.8.8.8 --max-pages 1 -o preview.json
```

### Fetch Existing Check Results

```bash
# Re-download results from previous check (no cost)
detect-expert fetch <check_id> <session_id> -o results.json

# Example:
detect-expert fetch cddec0733d6d4c9cb5f121483101435e 90ccc3317d6641b3ae17031211b7f5f2 -o results.json
```

### Other Commands

```bash
# View check history
detect-expert history

# Export as IP list only
detect-expert check 1.1.1.1 -o ips.txt -f ips

# Export as CSV
detect-expert check 1.1.1.1 -o data.csv -f csv
```

## Example Output

```
$ detect-expert check 8.8.8.8 -o results.json

🔐 Logging in as user@example.com...
✅ Authenticated. Balance: $49.25

📤 Starting DNS check for 8.8.8.8...
   📄 Page 15/21 | 1500 records

✅ Found 2099 DNS records
   URL: https://detect.expert/dnscheck/abc123/def456

📊 Top providers:
   Google LLC: 2099

📋 Sample records:
   8.8.8.8 - Google LLC
   8.8.4.4 - Google LLC
   35.186.235.154 - Google LLC
   ... and 2089 more

💾 Saved to results.json
```

## JSON Output Structure

```json
{
  "check_id": "84d34ccc84f14e1587dbacbf980703dd",
  "session_id": "984ff4f30ec64e8da47c2097d0daa56c",
  "ip_checked": "8.8.8.8",
  "url": "https://detect.expert/dnscheck/84d34ccc.../984ff4f3...",
  "total_records": 2099,
  "records": [
    {
      "ip": "8.8.8.8",
      "provider": "Google LLC",
      "country": "United States",
      "region": "CA",
      "city": "Mountain View"
    },
    {
      "ip": "35.186.235.154",
      "provider": "Google LLC",
      "country": "United States",
      "region": "MO",
      "city": "Kansas City"
    }
  ],
  "providers": {
    "Google LLC": 2099
  },
  "created_at": "2025-01-01T23:30:00.000000"
}
```

## Python API

```python
from detect_expert import DetectExpertClient

# Create client and login
client = DetectExpertClient()
client.login("your@email.com", "your_password")

# Run DNS check (fetches all pages)
result = client.check_dns("8.8.8.8")

print(f"Total DNS records: {result.total_records}")
print(f"Unique IPs: {len(result.unique_ips)}")

for record in result.records[:5]:
    print(f"{record.ip} | {record.provider} | {record.city}, {record.region}")
```

### Fetch with Progress Callback

```python
def on_progress(page: int, total_records: int, total_pages: int | None):
    if total_pages:
        print(f"Page {page}/{total_pages}: {total_records} records")
    else:
        print(f"Page {page}: {total_records} records")

# Fetch results with progress
records = list(client.fetch_results(
    check_id="abc123",
    session_id="def456",
    on_page=on_progress,
))
```

### API Reference

| Method | Description |
|--------|-------------|
| `login(email, password)` | Authenticate with detect.expert |
| `check_dns(ip, ...)` | Run DNS check for IP address |
| `fetch_results(check_id, session_id, ...)` | Fetch results from existing check |
| `get_history(limit=10)` | Get check history |

#### check_dns() Parameters

```python
result = client.check_dns(
    ip_address="8.8.8.8",   # IP to check
    wait_seconds=3.0,       # Wait before fetching (default: 3)
    fetch_results=True,     # Auto-fetch results (default: True)
    max_pages=300,          # Max pages to fetch (default: 300)
    page_delay=0.1,         # Delay between pages (default: 0.1)
)
```

#### fetch_results() Parameters

```python
records = client.fetch_results(
    check_id="abc123",
    session_id="def456",
    max_pages=300,          # Max pages (default: 300)
    delay=0.1,              # Delay between pages (default: 0.1)
    retry_delay=1.0,        # Retry delay for pending pages (default: 1.0)
    max_retries=15,         # Max retries per page (default: 15)
    on_page=callback,       # Progress callback (optional)
)
```

## CLI Options

```
detect-expert check <IP> [OPTIONS]
  -o, --output FILE     Save results to file
  -f, --format FORMAT   Output format: json, ips, csv (default: json)
  --wait SECONDS        Wait time after check (default: 3)
  --max-pages N         Max pages to fetch (default: 300)
  --delay SECONDS       Delay between requests (default: 0.1)
  -q, --quiet           Quiet mode

detect-expert fetch <CHECK_ID> <SESSION_ID> [OPTIONS]
  -o, --output FILE     Save results to file
  -f, --format FORMAT   Output format: json, ips, csv
  --max-pages N         Max pages to fetch
  --delay SECONDS       Delay between requests

detect-expert history
  -l, --limit N         Max items to show (default: 10)
```

## How It Works

### Why This Works

Standard HTTP libraries (`requests`, `httpx`, `aiohttp`) fail against Cloudflare because their TLS fingerprint doesn't match any known browser. Cloudflare blocks them with 403/503 errors.

This client uses [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) which:
- Impersonates Chrome's exact TLS handshake (cipher suites, extensions, ALPN)
- Passes Cloudflare's JA3/JA4 fingerprint checks
- No Selenium, Playwright, or browser automation needed

```
requests/httpx ────────────> [Cloudflare] ❌ 403 Forbidden

detect-expert-client ──────> [Cloudflare] ✅ Pass ──> [detect.expert]
    └── Chrome TLS fingerprint
```

### Technical Details

1. **TLS Fingerprinting**: Impersonates `chrome_131` TLS profile
2. **CSRF Handling**: Extracts tokens from forms and cookies for Django backend
3. **Smart Pagination**: Retries pages returning "retry" status (check still processing)
4. **Progress Tracking**: Detects total pages from pagination links

## Requirements

- Python 3.10+
- [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) >= 1.0.0
- detect.expert account with balance

## What is DNS Check?

DNS check on detect.expert shows all DNS resolvers that have queried your IP address. This reveals:

- **VPN/Proxy detection** — If DNS requests come from different IPs than the connection IP
- **ISP information** — Provider names, geographic locations of DNS servers
- **DNS leak detection** — Shows if your real DNS servers are exposed

The service sends a unique DNS query to your IP and logs all resolvers that look it up.

## Pricing

Each DNS check costs **$0.15** on detect.expert. Fetching existing results is free.

## Links

- **PyPI**: [detect-expert-client](https://pypi.org/project/detect-expert-client/)
- **Docker Hub**: [mazamaka/detect-expert-client](https://hub.docker.com/r/mazamaka/detect-expert-client)
- **GitHub**: [mazamaka/detect-expert-client](https://github.com/mazamaka/detect-expert-client)

## License

MIT License - see [LICENSE](LICENSE) file.

## Disclaimer

This tool is for educational and authorized testing purposes only. The author is not responsible for any misuse. Make sure you comply with detect.expert's Terms of Service.
