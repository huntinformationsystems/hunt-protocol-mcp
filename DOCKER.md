# Docker Support - Design Rationale

## Overview

This document explains the design decisions behind the Docker support for Provara MCP. The implementation aims to preserve user sovereignty over vault data and avoid baking secrets into images.

## Key Decisions

- No vault content is baked into the image — not even the example vault. All vaults must be mounted at runtime via Docker volumes.
- Signing keys are injected only via environment variables (`HUNT_SIGNING_KEY_B64`).
- Use `python:3.11-slim` to keep the image minimal and reduce attack surface.
- No ports are exposed; MCP uses stdin/stdout for communication.

## Security Rationale

- Sovereignty: Vault data remains on the host and is mounted at `/vault`.
- Secrets: Signing keys are never written into image layers or repo files.
- Improved build reproducibility: `--no-cache-dir` pip installs and minimal COPY steps; fully deterministic rebuilds additionally require pinning the base image digest and all Python dependency versions (for example via a constraints or lock file).

## Quick Start

Read-only (reference vault):

```bash
docker-compose up
```

With a custom vault:

```bash
HUNT_VAULT_PATH=/path/to/vault docker-compose up
```

Enable write operations (inject signing key):

```bash
HUNT_VAULT_PATH=/path/to/vault \
  HUNT_SIGNING_KEY_B64="your-base64-ed25519-key" \
  docker-compose up
```

## Future Improvements

- Multi-stage build to reduce final image size
- Add non-root user in container for hardening
- Optional image signing for supply-chain security
