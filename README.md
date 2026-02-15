# Provara

**Sovereign Memory for AI Systems**

[![PyPI version](https://img.shields.io/pypi/v/provara)](https://pypi.org/project/provara/)
[![Python 3.10+](https://img.shields.io/pypi/pyversions/provara)](https://pypi.org/project/provara/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](https://github.com/huntinformationsystems/hunt-protocol-mcp/blob/main/LICENSE)
[![MCP compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

---

Every AI agent framework shipping today has a memory problem. Not a context-window problem -- a **trust** problem.

Mem0, Zep, LangChain memory -- they all store your agent's cognitive state on someone else's servers, in someone else's format, behind someone else's API key. When that service pivots, gets acquired, or shuts down, your agent's memory goes with it. No export. No verification. No proof that what you get back is what you put in.

**Provara** is an MCP server that gives AI agents tamper-evident, cryptographically signed, offline-first memory. Every observation is hash-chained. Every belief is recomputable from evidence. Every vault is verifiable with a single command. Your agent's memory belongs to you -- not to a platform.

## Quickstart

Install from PyPI and run against the included reference vault:

```bash
pip install provara
hunt-mcp
```

That starts the MCP server with a working vault, ready for any MCP-compatible client. Under 60 seconds from zero to running.

### Connect to Claude Code

```bash
claude mcp add provara -- hunt-mcp
```

### Point at your own vault

```bash
HUNT_VAULT_PATH=/path/to/vault hunt-mcp
```

### Enable write operations

```bash
HUNT_VAULT_PATH=/path/to/vault \
  HUNT_SIGNING_KEY_B64="your-base64-ed25519-private-key" \
  hunt-mcp
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

## Why Provara?

**Tamper-evident.** Every event is cryptographically signed with Ed25519 and hash-chained. Any modification -- even a single flipped bit -- breaks the causal chain and fails verification. The vault seals itself with a Merkle tree and a signed manifest.

**Offline-first.** No cloud dependency. No phone-home. No telemetry. Provara works air-gapped, on a USB drive, on a robot in a warehouse with no internet connection. Sovereignty means the system works without asking anyone for permission.

**One dependency.** The protocol layer imports exactly one external package: `cryptography` (>= 41.0). The MCP server adds `fastmcp`. That is the entire dependency tree. No framework rot. No transitive supply-chain risk worth worrying about.

**Deterministic.** Same events, same reducer, same state -- on any machine, any time, forever. Canonical JSON serialization (RFC 8785), SHA-256 hashing (FIPS 180-4), Ed25519 signatures (RFC 8032). Two implementations in different languages must produce byte-identical output for the same input. If the hashes match, the implementation is correct.

**Auditable.** The event log is NDJSON. Open it in a text editor. Read it. The vault is a directory of plain files. No proprietary format. No binary blob. No database engine between you and your data.

## How It Works

Every vault is a directory containing:

- **events/events.ndjson** -- Append-only event log (signed, content-addressed)
- **identity/** -- Genesis record + public key registry
- **policies/** -- Safety policy, sync contract, retention rules
- **manifest.json** -- Deterministic file index with SHA-256 hashes
- **merkle_root.txt** -- Integrity anchor (Merkle tree root)

The MCP server loads events, runs a deterministic reducer to compute state across four namespaces (canonical, local, contested, archived), and exposes everything through typed tools. Truth is not merged -- evidence is merged, and truth is recomputed.

## Architecture

The server wraps the Provara L0 protocol modules:

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

Seven modules. 110 tests. One external dependency. The protocol spec is frozen at L0.

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
HUNT_VAULT_PATH=./my_vault HUNT_SIGNING_KEY_B64="<private-key>" hunt-mcp
```

## Claude Code Integration

Register the server with Claude Code for direct tool access:

```bash
claude mcp add provara -- hunt-mcp
```

With a custom vault and write access:

```bash
claude mcp add provara \
  -e HUNT_VAULT_PATH=/path/to/vault \
  -e HUNT_SIGNING_KEY_B64="your-key-here" \
  -- hunt-mcp
```

## Links

- **Homepage:** [provara.dev](https://provara.dev)
- **Repository:** [github.com/huntinformationsystems/hunt-protocol-mcp](https://github.com/huntinformationsystems/hunt-protocol-mcp)
- **PyPI:** [pypi.org/project/provara](https://pypi.org/project/provara/)

## License

Apache 2.0 -- Provara
