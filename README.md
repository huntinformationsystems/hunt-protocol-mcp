# Hunt Protocol MCP Server

MCP server that exposes Hunt Protocol sovereign memory operations as tools. Connect any MCP-compatible AI client (Claude Code, Claude Desktop, ChatGPT via bridge) to a cryptographically signed, append-only vault with deterministic state reduction.

**Category:** Sovereign AI Memory via MCP
**Status:** Shipped v0.1.0

## Install

```bash
cd hunt-mcp
pip install .
```

Requires Python 3.10+. Dependencies: `fastmcp>=2.0`, `cryptography>=41.0`.

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

## How It Works

Every vault is a directory containing:

- **events/events.ndjson** — Append-only event log (signed, content-addressed)
- **identity/** — Genesis record + public key registry
- **policies/** — Safety policy, sync contract, retention rules
- **manifest.json** — Deterministic file index with SHA-256 hashes
- **merkle_root.txt** — Integrity anchor (Merkle tree root)

The MCP server loads events, runs a deterministic reducer to compute state across four namespaces (canonical, local, contested, archived), and exposes everything through typed tools.

## Architecture

The server wraps the Hunt Protocol L0 modules:

| Module | Responsibility |
|--------|---------------|
| `canonical_json` | RFC 8785 deterministic JSON serialization |
| `integrity` | SHA-256 file hashing, Merkle trees, path safety |
| `signing` | Ed25519 keypair management, event/manifest signing |
| `reducer` | Deterministic four-namespace state reducer |
| `manifest` | Manifest generation and verification |
| `sync` | Event log I/O, causal chain verification, fork detection |
| `bootstrap` | Vault creation from scratch |
| `rekey` | Key rotation protocol |

## Creating a New Vault

```python
from hunt_protocol.bootstrap import bootstrap_backpack
from pathlib import Path

result = bootstrap_backpack(Path("./my_vault"))
print(f"UID: {result.uid}")
print(f"Root key: {result.root_key_id}")
print(f"Private key (save this!): {result.root_private_key_b64}")
```

Then point the server at it:

```bash
HUNT_VAULT_PATH=./my_vault HUNT_SIGNING_KEY_B64="<private-key>" python server.py
```

## License

Apache 2.0 — Hunt Information Systems LLC
