# Docker Hub Description

## Short Description (100 chars max)
```
Python CLI for detect.expert DNS checks. Bypasses Cloudflare using TLS fingerprinting - no browser!
```

## Full Description (copy to Docker Hub)

# Detect Expert DNS Check Client

Python client for [detect.expert](https://detect.expert) DNS checking service with Cloudflare bypass.

## Features

- **Cloudflare Bypass** — TLS fingerprinting (no Selenium/Playwright needed)
- **Full Pagination** — Fetches all pages with progress indicator
- **Export** — JSON, CSV, or plain IP list

## Quick Start

```bash
# Run DNS check
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p your_password \
  check 8.8.8.8

# Save results to file
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p your_password \
  check 8.8.8.8 -o /data/results.json

# Fetch existing check results
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p your_password \
  fetch <check_id> <session_id> -o /data/results.json

# View history
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p your_password \
  history
```

## Environment Variables

Instead of `-e` and `-p` flags:

```bash
docker run --rm \
  -e DETECT_EXPERT_EMAIL=your@email.com \
  -e DETECT_EXPERT_PASSWORD=your_password \
  mazamaka/detect-expert-client check 8.8.8.8
```

## Links

- **GitHub**: https://github.com/mazamaka/detect-expert-client
- **detect.expert**: https://detect.expert

## License

MIT License
