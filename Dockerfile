FROM python:3.11-slim

WORKDIR /app

# Copy minimal files needed to install the package
COPY pyproject.toml ./
COPY README.md ./
COPY server.py ./
COPY hunt_protocol/ ./hunt_protocol/
COPY examples/ ./examples/

# Install the package in editable mode so the image reflects source
RUN pip install --no-cache-dir -e .

# Mount point for vault (always provided by the host)
RUN mkdir -p /vault
ENV HUNT_VAULT_PATH=/vault

# MCP uses stdio for communication; run the CLI entrypoint
CMD ["hunt-mcp"]
