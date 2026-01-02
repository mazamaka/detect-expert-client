FROM python:3.11-slim

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY detect_expert/ detect_expert/

# Install package
RUN pip install --no-cache-dir .

# Set entrypoint
ENTRYPOINT ["detect-expert"]
CMD ["--help"]
