# detect-expert-client

DNS check client for [detect.expert](https://detect.expert) with Cloudflare bypass via TLS fingerprinting.

---

## Commands

| Command | Description |
|---------|-------------|
| `check <IP>` | Run DNS check ($0.15 per check) |
| `fetch <check_id> <session_id>` | Download existing results (free) |
| `history` | View check history |

---

## Options

| Option | Description |
|--------|-------------|
| `-e, --email` | Account email |
| `-p, --password` | Account password |
| `-o, --output FILE` | Save to file |
| `-f, --format` | Format: `json`, `csv`, `ips` |
| `--max-pages N` | Limit pages (default: 300) |
| `--wait SEC` | Wait after check (default: 3) |
| `-q, --quiet` | Quiet mode |

---

## Examples

```bash
# Basic check
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p password \
  check 8.8.8.8

# Save JSON to file
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p password \
  check 8.8.8.8 -o /data/results.json

# Export as IP list
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p password \
  check 8.8.8.8 -o /data/ips.txt -f ips

# Fetch existing check (free)
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p password \
  fetch abc123 def456 -o /data/results.json

# View history
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p password \
  history -l 20
```

---

## Environment Variables

```bash
docker run --rm \
  -e DETECT_EXPERT_EMAIL=your@email.com \
  -e DETECT_EXPERT_PASSWORD=password \
  mazamaka/detect-expert-client check 8.8.8.8
```

---

**GitHub:** [mazamaka/detect-expert-client](https://github.com/mazamaka/detect-expert-client)
