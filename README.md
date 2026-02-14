# Hunt Protocol MCP Server

MCP server that exposes Hunt Protocol sovereign memory operations as tools. Connect any MCP-compatible AI client (Claude Code, Claude Desktop, ChatGPT via bridge) to a cryptographically signed, append-only vault with deterministic state reduction.

## Install

```bash
cd hunt-mcp
pip install .
```

## Quick Start

```bash
# Run against the included reference backpack
python server.py

# Run against your own vault
HUNT_VAULT_PATH=/path/to/vault python server.py

# Enable write operations (observations + assertions)
HUNT_SIGNING_KEY_B64="your-base64-ed25519-private-key" python server.py
```

## Claude Code Integration

```bash
claude mcp add hunt-protocol -- python /path/to/hunt-mcp/server.py
```

With a custom vault:

```bash
claude mcp add hunt-protocol -e HUNT_VAULT_PATH=/path/to/vault -- python /path/to/hunt-mcp/server.py
```

With write access:

```bash
claude mcp add hunt-protocol \
  -e HUNT_VAULT_PATH=/path/to/vault \
  -e HUNT_SIGNING_KEY_B64="your-key-here" \
  -- python /path/to/hunt-mcp/server.py
```

## Tools

### Read Tools (no key required)

| Tool | Description |
|------|-------------|
| `vault_status` | Vault health: event count, state hash, merkle root, key info, compliance summary |
| `list_events` | List events with filters (type, actor, namespace, limit, offset) |
| `get_event` | Full event by event_id |
| `get_state` | Current reduced state (all namespaces or filtered) |
| `get_beliefs` | Query beliefs by namespace, optional key pattern (subject:predicate) |
| `get_evidence` | Evidence trail for a specific belief key |
| `verify_vault` | Run integrity + compliance checks, return pass/fail details |
| `search_events` | Search events by payload content (subject, predicate, value substring) |

### Write Tools (require `HUNT_SIGNING_KEY_B64`)

| Tool | Description |
|------|-------------|
| `append_observation` | Add observation: subject, predicate, value, confidence |
| `append_assertion` | Add assertion: subject, predicate, value, confidence |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HUNT_VAULT_PATH` | No | Path to vault directory (default: `./examples/reference_backpack`) |
| `HUNT_SIGNING_KEY_B64` | For writes | Base64-encoded Ed25519 private key |

## Architecture

The server wraps the Hunt Protocol L0 modules:

- **canonical_json** — RFC 8785 deterministic JSON serialization
- **integrity** — SHA-256 file hashing, Merkle trees, path safety
- **signing** — Ed25519 keypair management, event/manifest signing
- **reducer** — Deterministic four-namespace state reducer
- **manifest** — Manifest generation and verification
- **sync** — Event log I/O, causal chain verification, fork detection
- **bootstrap** — Vault creation from scratch
- **rekey** — Key rotation protocol

## License

Apache 2.0 — Hunt Information Systems LLC
