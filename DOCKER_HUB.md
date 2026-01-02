# detect-expert-client

DNS check client for [detect.expert](https://detect.expert) with Cloudflare bypass.

## Usage

```bash
# DNS check
docker run --rm mazamaka/detect-expert-client \
  -e your@email.com -p password check 8.8.8.8

# Save to file
docker run --rm -v $(pwd):/data mazamaka/detect-expert-client \
  -e your@email.com -p password check 8.8.8.8 -o /data/results.json
```

## Links

- [GitHub](https://github.com/mazamaka/detect-expert-client)
- [detect.expert](https://detect.expert)
