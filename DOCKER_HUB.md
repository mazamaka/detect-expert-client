# detect-expert-client

DNS check client for [detect.expert](https://detect.expert) with Cloudflare bypass via TLS fingerprinting.

---

## Commands

| Command | Description |
|---------|-------------|
| `check <IP>` | Run DNS check for IP address |
| `fetch <check_id> <session_id>` | Download existing check results |
| `history` | View check history |

---

## Quick Start

```bash
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p password \
  check 8.8.8.8
```

## Save Results

```bash
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p password \
  check 8.8.8.8 -o /data/results.json
```

## Output Formats

- `-f json` — Full data with provider, country, region, city
- `-f csv` — CSV table
- `-f ips` — Plain IP list

---

**GitHub:** [mazamaka/detect-expert-client](https://github.com/mazamaka/detect-expert-client)
