# Detect Expert DNS Check Client

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python client for [detect.expert](https://detect.expert) DNS checking service.

**Key feature:** Bypasses Cloudflare protection using TLS fingerprinting — no browser required!

## Features

- 🔓 **Cloudflare Bypass** — Uses [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) to impersonate Chrome TLS fingerprint
- 🚀 **Fast** — Pure HTTP requests, no browser overhead
- 📦 **Simple API** — Clean, typed Python interface
- 🖥️ **CLI Tool** — Command-line interface included
- 💾 **Export** — JSON, CSV, or plain IP list

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

## Quick Start

### Python API

```python
from detect_expert import DetectExpertClient

# Create client and login
client = DetectExpertClient()
client.login("your@email.com", "your_password")

# Run DNS check
result = client.check_dns("8.8.8.8")

# Access results
print(f"Total DNS records: {result.total_records}")
print(f"Unique IPs: {len(result.unique_ips)}")

for record in result.records[:5]:
    print(f"{record.ip} - {record.provider} ({record.country})")
```

### Command Line

```bash
# Set credentials (or use -e/-p flags)
export DETECT_EXPERT_EMAIL="your@email.com"
export DETECT_EXPERT_PASSWORD="your_password"

# Run DNS check
detect-expert check 8.8.8.8 -o results.json

# Check with IP list output
detect-expert check 1.1.1.1 -o ips.txt -f ips

# View check history
detect-expert history

# Fetch existing check results
detect-expert fetch <check_id> <session_id> -o results.json
```

## Example Results

### DNS Check for Google DNS (8.8.8.8)

```
🔐 Logging in...
✅ Authenticated! Balance: $49.55

📤 Checking DNS for 8.8.8.8...
✅ Check completed!
   Total records: 100
   Unique IPs: 100
   URL: https://detect.expert/dnscheck/abc123/def456

📊 Providers:
   Google LLC: 85
   Cloudflare, Inc.: 15

📋 Sample records:
   35.186.235.154 | Google LLC | US
   8.8.4.4 | Google LLC | US
   35.208.84.233 | Google LLC | US
   35.206.6.107 | Google LLC | US
   35.186.255.253 | Google LLC | US
   ... and 95 more

💾 Results saved to results.json
```

### JSON Output Structure

```json
{
  "check_id": "84d34ccc84f14e1587dbacbf980703dd",
  "session_id": "984ff4f30ec64e8da47c2097d0daa56c",
  "ip_checked": "8.8.8.8",
  "url": "https://detect.expert/dnscheck/84d34ccc.../984ff4f3...",
  "total_records": 100,
  "records": [
    {
      "ip": "35.186.235.154",
      "provider": "Google LLC",
      "country": "United States",
      "region": "",
      "city": ""
    },
    {
      "ip": "8.8.4.4",
      "provider": "Google LLC",
      "country": "United States",
      "region": "",
      "city": ""
    }
  ],
  "providers": {
    "Google LLC": 85,
    "Cloudflare, Inc.": 15
  },
  "created_at": "2025-01-01T23:30:00.000000"
}
```

## API Reference

### DetectExpertClient

```python
from detect_expert import DetectExpertClient

client = DetectExpertClient(
    browser="chrome_131",  # Browser to impersonate
    timeout=30,            # Request timeout
)
```

#### Methods

| Method | Description |
|--------|-------------|
| `login(email, password)` | Authenticate with detect.expert |
| `check_dns(ip, ...)` | Run DNS check for IP address |
| `fetch_results(check_id, session_id)` | Fetch results from existing check |
| `get_history(limit=10)` | Get check history |

#### check_dns() Parameters

```python
result = client.check_dns(
    ip_address="8.8.8.8",   # IP to check
    wait_seconds=3.0,       # Wait for results
    fetch_results=True,     # Fetch results automatically
    max_pages=300,          # Max pages to fetch
    page_delay=0.2,         # Delay between requests
)
```

### CheckResult

```python
result.check_id        # Check ID
result.session_id      # Session ID
result.ip_checked      # Checked IP
result.url             # Result URL
result.total_records   # Total DNS records count
result.unique_ips      # List of unique IPs
result.providers       # Provider statistics dict
result.records         # List of DNSRecord objects
result.to_dict()       # Convert to dictionary
result.to_ip_list()    # Get list of IPs only
```

### DNSRecord

```python
record.ip        # DNS IP address
record.provider  # ISP/Provider name
record.country   # Country
record.region    # Region/State
record.city      # City
```

## How It Works

1. **TLS Fingerprinting**: Uses [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) to impersonate Chrome's TLS handshake, bypassing Cloudflare's bot detection
2. **Session Management**: Maintains authenticated session with CSRF token handling
3. **AJAX Requests**: Uses the same endpoints as the browser for seamless integration

```
[Python Client] --Chrome TLS Fingerprint--> [Cloudflare] ✅ Pass --> [detect.expert]
```

## Requirements

- Python 3.10+
- [tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client) >= 1.0.0
- detect.expert account with balance

## Pricing

Each DNS check costs **$0.15** on detect.expert. Check your balance in the web interface or via API.

## License

MIT License - see [LICENSE](LICENSE) file.

## Disclaimer

This tool is for educational and authorized testing purposes only. Make sure you comply with detect.expert's Terms of Service.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
