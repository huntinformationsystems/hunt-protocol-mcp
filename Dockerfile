FROM python:3.11.8-slim

WORKDIR /app

# Copy minimal files needed to install the package
COPY pyproject.toml ./
COPY README.md ./
COPY hunt_protocol/ ./hunt_protocol/

# Install the package in non-editable mode for reproducible runtime images
RUN pip install --no-cache-dir .

# Mount point for vault (always provided by the host)
RUN mkdir -p /vault
ENV HUNT_VAULT_PATH=/vault

# MCP uses stdio for communication; run the CLI entrypoint
CMD ["hunt-mcp"]
