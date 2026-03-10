# Detect Expert DNS Check Client

[![PyPI](https://img.shields.io/pypi/v/detect-expert-client?color=blue)](https://pypi.org/project/detect-expert-client/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/docker/v/mazamaka/detect-expert-client?label=docker&color=blue)](https://hub.docker.com/r/mazamaka/detect-expert-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

Python client for [detect.expert](https://detect.expert) DNS checking service with **Cloudflare bypass** via TLS fingerprinting.

> Standard HTTP libraries (requests, httpx, aiohttp) get blocked by Cloudflare with 403/503 errors.
> This client impersonates Chrome TLS handshake to pass JA3/JA4 fingerprint checks -- no browser automation needed.

## How TLS Fingerprinting Works

When a client establishes an HTTPS connection, the TLS handshake reveals a unique fingerprint (JA3/JA4) based on:
- Cipher suites offered
- TLS extensions and their order
- Supported curves and point formats
- ALPN protocols

Cloudflare uses this fingerprint to distinguish real browsers from bots. Standard Python HTTP libraries have a recognizable non-browser fingerprint and get blocked.

This client uses [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) (Go library with Python bindings) to produce a TLS fingerprint **identical to Chrome 131**, making requests indistinguishable from a real browser at the network level.

```
requests/httpx ------> [Cloudflare] BLOCKED (bot TLS fingerprint)

detect-expert -------> [Cloudflare] PASS -----> [detect.expert]
  (Chrome TLS)
```

## Features

- **Cloudflare Bypass** -- Chrome TLS fingerprint via [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client)
- **Smart Pagination** -- auto-fetches all pages with retry logic for pending results
- **Full Data** -- IP, provider, country, region, city for each DNS resolver
- **CLI Tool** -- command-line interface with real-time progress
- **Export** -- JSON, CSV, or plain IP list
- **Docker** -- ready-to-use container image

## Quick Start

### Install

```bash
pip install detect-expert-client
```

### Set Credentials

```bash
export DETECT_EXPERT_EMAIL="your@email.com"
export DETECT_EXPERT_PASSWORD="your_password"
```

### Run DNS Check

```bash
# Full check -- fetches ALL pages automatically
detect-expert check 8.8.8.8 -o results.json

# Quick preview -- first page only
detect-expert check 8.8.8.8 --max-pages 1

# Export as IP list
detect-expert check 1.1.1.1 -o ips.txt -f ips

# Export as CSV
detect-expert check 1.1.1.1 -o data.csv -f csv
```

### Re-download Existing Results (Free)

```bash
detect-expert fetch <check_id> <session_id> -o results.json
```

### View History

```bash
detect-expert history
```

## Python API

```python
from detect_expert import DetectExpertClient

client = DetectExpertClient()
client.login("your@email.com", "your_password")

# Run DNS check (auto-fetches all pages)
result = client.check_dns("8.8.8.8")

for record in result.records[:5]:
    pass  # record.ip, record.provider, record.city
```

### Progress Callback

```python
def on_progress(page: int, total_records: int, total_pages: int | None):
    pass  # page, total_pages, total_records

records = list(client.fetch_results(
    check_id="abc123",
    session_id="def456",
    on_page=on_progress,
))
```

### Error Handling

```python
from detect_expert import (
    DetectExpertClient,
    AuthenticationError,
    InsufficientFundsError,
    RateLimitError,
    CheckError,
)

client = DetectExpertClient()

try:
    client.login("your@email.com", "your_password")
    result = client.check_dns("8.8.8.8")
except AuthenticationError:
    ...
except InsufficientFundsError:
    ...  # each check costs $0.15
except RateLimitError:
    ...  # too many requests
except CheckError as e:
    ...  # check failed
```

## API Reference

### ```DetectExpertClient(browser, timeout)```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| ```browser``` | ```str``` | ```"chrome_131"``` | TLS profile to impersonate |
| ```timeout``` | ```int``` | ```30``` | Request timeout in seconds |

### ```client.login(email, password) -> AccountInfo```

Authenticates with detect.expert. Returns ```AccountInfo``` with ```email```, ```balance```, ```is_authenticated```.

### ```client.check_dns(ip_address, ...) -> CheckResult```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| ```ip_address``` | ```str``` | *required* | IPv4 or IPv6 address |
| ```wait_seconds``` | ```float``` | ```3.0``` | Wait before fetching results |
| ```fetch_results``` | ```bool``` | ```True``` | Auto-fetch results |
| ```max_pages``` | ```int``` | ```300``` | Max pages to fetch |
| ```page_delay``` | ```float``` | ```0.2``` | Delay between pages (seconds) |

### ```client.fetch_results(check_id, session_id, ...) -> Iterator[DNSRecord]```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| ```check_id``` | ```str``` | *required* | Check ID |
| ```session_id``` | ```str``` | *required* | Session ID |
| ```max_pages``` | ```int``` | ```300``` | Max pages to fetch |
| ```delay``` | ```float``` | ```0.1``` | Delay between pages (seconds) |
| ```retry_delay``` | ```float``` | ```1.0``` | Retry delay for pending pages |
| ```max_retries``` | ```int``` | ```15``` | Max retries per page |
| ```on_page``` | ```Callable``` | ```None``` | Progress callback |

### ```client.get_history(limit=10) -> list[dict]```

Returns list of ```{"check_id": ..., "session_id": ...}``` dicts.

### Data Models

**```CheckResult```** -- DNS check result:
- ```check_id```, ```session_id```, ```ip_checked```, ```url```
- ```records: list[DNSRecord]```
- ```total_records```, ```unique_ips```, ```providers``` (stats dict)
- ```to_dict()```, ```to_ip_list()```

**```DNSRecord```** -- single DNS resolver record:
- ```ip```, ```provider```, ```country```, ```region```, ```city```
- ```to_dict()```

## CLI Reference

```
detect-expert [-e EMAIL] [-p PASSWORD] [-v] COMMAND

Commands:
  check <IP>                          Run DNS check ($0.15)
  fetch <CHECK_ID> <SESSION_ID>       Fetch existing results (free)
  history                             View check history

check options:
  -o, --output FILE       Save results to file
  -f, --format FORMAT     json | ips | csv (default: json)
  --wait SECONDS          Wait after check start (default: 3)
  --max-pages N           Max pages to fetch (default: 300)
  --delay SECONDS         Delay between requests (default: 0.2)
  -q, --quiet             Suppress sample output

fetch options:
  -o, --output FILE       Save results to file
  -f, --format FORMAT     json | ips | csv (default: json)
  --max-pages N           Max pages to fetch (default: 300)
  --delay SECONDS         Delay between requests (default: 0.2)

history options:
  -l, --limit N           Max items to show (default: 10)
```

## Output Formats

### JSON

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
    }
  ],
  "providers": {"Google LLC": 2099},
  "created_at": "2025-01-01T23:30:00+00:00"
}
```

### IP List (```-f ips```)

```
8.8.8.8
8.8.4.4
35.186.235.154
```

### CSV (```-f csv```)

```csv
ip,provider,country,region,city
8.8.8.8,Google LLC,United States,CA,Mountain View
```

## Docker

```bash
# Pull and run
docker pull mazamaka/detect-expert-client:latest

docker run --rm \
  -e DETECT_EXPERT_EMAIL=your@email.com \
  -e DETECT_EXPERT_PASSWORD=your_password \
  mazamaka/detect-expert-client check 8.8.8.8

# Save results to host
docker run --rm -v $(pwd):/data \
  -e DETECT_EXPERT_EMAIL=your@email.com \
  -e DETECT_EXPERT_PASSWORD=your_password \
  mazamaka/detect-expert-client check 8.8.8.8 -o /data/results.json
```

## What is DNS Check?

DNS check on detect.expert shows all DNS resolvers that have queried your IP address. This reveals:

- **VPN/Proxy detection** -- DNS requests from different IPs than the connection IP
- **ISP information** -- provider names, geographic locations of DNS servers
- **DNS leak detection** -- real DNS servers exposed despite VPN/proxy usage

The service sends a unique DNS query to your IP and logs all resolvers that look it up. Each check costs **$0.15**. Fetching existing results is free.

## Requirements

- Python 3.10+
- [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) >= 1.0.0
- detect.expert account with balance

## Links

- **PyPI**: [detect-expert-client](https://pypi.org/project/detect-expert-client/)
- **Docker Hub**: [mazamaka/detect-expert-client](https://hub.docker.com/r/mazamaka/detect-expert-client)
- **GitHub**: [mazamaka/detect-expert-client](https://github.com/mazamaka/detect-expert-client)

## Author

**Maksym Babenko**
- GitHub: [@mazamaka](https://github.com/mazamaka)
- Telegram: [@Mazamaka](https://t.me/Mazamaka)

## License

MIT License -- see [LICENSE](LICENSE) file.

## Disclaimer

This tool is for educational and authorized testing purposes only. The author is not responsible for any misuse. Make sure you comply with detect.expert Terms of Service.
