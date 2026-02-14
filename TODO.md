# Hunt Protocol MCP Server — TODO

## Next Up
- [ ] Bootstrap a real vault with live signing keys (replace reference backpack)
- [ ] Update corporate site Projects section — Hunt Protocol MCP is shipped, not "Coming Soon"
- [ ] Add to PyPI (`pip install hunt-protocol-mcp` from anywhere)

## Server Enhancements
- [ ] Add `bootstrap_vault` tool — create new vaults directly from MCP
- [ ] Add `attest_belief` tool — promote local beliefs to canonical (requires authority key)
- [ ] Add `export_delta` / `import_delta` tools — sync between vaults via MCP
- [ ] Add `rotate_key` tool — key rotation via MCP
- [ ] Add `get_manifest` tool — return current manifest + merkle root
- [ ] Resource endpoints — expose vault files as MCP resources (not just tools)
- [ ] SSE transport option — for remote/cloud deployments

## Testing & Quality
- [ ] Add test suite for server.py (unit tests for each tool)
- [ ] CI pipeline — GitHub Actions for lint + test on push
- [ ] Test with Claude Desktop (not just Claude Code)
- [ ] Test with ChatGPT via MCP bridge

## Distribution
- [ ] PyPI publish workflow
- [ ] Docker image (`docker run huntinformationsystems/hunt-mcp`)
- [ ] npm wrapper for Node.js MCP clients
- [ ] Claude Desktop config example in README

## Protocol Evolution
- [ ] Checkpoint system — signed state snapshots for fast startup
- [ ] Multi-vault support — serve multiple vaults from one server
- [ ] Vault discovery — auto-detect vaults in a directory tree
- [ ] Cross-language clients — Rust, Go, TypeScript passing compliance tests
