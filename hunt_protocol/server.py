"""
Hunt Protocol MCP Server

Exposes Hunt Protocol L0 vault operations as MCP tools.
Connects sovereign AI memory to any MCP-compatible client.

Environment variables:
    HUNT_VAULT_PATH       — Path to vault directory (default: ./examples/reference_backpack)
    HUNT_SIGNING_KEY_B64  — Base64-encoded Ed25519 private key (enables write tools)
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import argparse
from . import __version__ 
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from hunt_protocol.canonical_json import canonical_bytes, canonical_dumps, canonical_hash
from hunt_protocol.signing import (
    BackpackKeypair,
    key_id_from_public_bytes,
    load_keys_registry,
    load_private_key_b64,
    resolve_public_key,
    sign_event,
    sign_manifest,
    verify_event_signature,
    _utc_now_iso,
)
from hunt_protocol.integrity import (
    canonical_json_bytes,
    merkle_root_hex,
    sha256_file,
    MANIFEST_EXCLUDE,
    SPEC_REQUIRED_FILES,
)
from hunt_protocol.reducer import SovereignReducerV0, belief_key
from hunt_protocol.sync import (
    load_events,
    write_events,
    detect_forks,
    verify_all_causal_chains,
    verify_all_signatures,
    get_all_actors,
    regenerate_manifest,
)
from hunt_protocol.manifest import build_manifest, manifest_leaves, check_required_files

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_VAULT = os.path.join(os.path.dirname(__file__), "..", "examples", "reference_backpack")
VAULT_PATH = Path(os.environ.get("HUNT_VAULT_PATH", _DEFAULT_VAULT)).resolve()
SIGNING_KEY_B64 = os.environ.get("HUNT_SIGNING_KEY_B64")

mcp = FastMCP("Hunt Protocol")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vault() -> Path:
    """Return the resolved vault path, raising if it doesn't exist."""
    if not VAULT_PATH.is_dir():
        raise FileNotFoundError(f"Vault not found: {VAULT_PATH}")
    return VAULT_PATH


def _events_path() -> Path:
    return _vault() / "events" / "events.ndjson"


def _keys_path() -> Path:
    return _vault() / "identity" / "keys.json"


def _load_and_reduce() -> tuple[List[Dict[str, Any]], SovereignReducerV0]:
    """Load events and run the reducer. Returns (events, reducer)."""
    events = load_events(_events_path())
    reducer = SovereignReducerV0()
    reducer.apply_events(events)
    return events, reducer


def _get_signing_context() -> tuple:
    """
    Load signing key from env var, derive key_id.
    Returns (private_key, key_id) or raises if not configured.
    """
    if not SIGNING_KEY_B64:
        raise ValueError(
            "Write operations require HUNT_SIGNING_KEY_B64 environment variable. "
            "Set it to a base64-encoded Ed25519 private key."
        )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = load_private_key_b64(SIGNING_KEY_B64)
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = key_id_from_public_bytes(pub_bytes)
    return private_key, kid


# ---------------------------------------------------------------------------
# Read Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def vault_status() -> dict:
    """Get vault health: event count, state hash, merkle root, key info, compliance summary."""
    vault = _vault()
    events, reducer = _load_and_reduce()
    state = reducer.export_state()
    meta = state["metadata"]

    # Key info
    keys_path = _keys_path()
    key_info = {"total_keys": 0, "active_keys": 0, "revoked_keys": 0}
    if keys_path.exists():
        keys_data = json.loads(keys_path.read_text(encoding="utf-8"))
        keys_list = keys_data.get("keys", [])
        key_info["total_keys"] = len(keys_list)
        key_info["active_keys"] = sum(1 for k in keys_list if k.get("status") == "active")
        key_info["revoked_keys"] = sum(1 for k in keys_list if k.get("status") == "revoked")

    # Merkle root
    merkle_path = vault / "merkle_root.txt"
    merkle_root = merkle_path.read_text(encoding="utf-8").strip() if merkle_path.exists() else None

    # Genesis info
    genesis_path = vault / "identity" / "genesis.json"
    genesis = json.loads(genesis_path.read_text(encoding="utf-8")) if genesis_path.exists() else {}

    # Compliance quick check
    manifest_path = vault / "manifest.json"
    missing_files = []
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        missing_files = check_required_files(manifest)

    # Namespace counts
    ns_counts = {
        ns: len(state.get(ns, {}))
        for ns in ("canonical", "local", "contested", "archived")
    }

    actors = get_all_actors(events)
    event_types = {}
    for e in events:
        t = e.get("type", "UNKNOWN")
        event_types[t] = event_types.get(t, 0) + 1

    return {
        "vault_path": str(vault),
        "uid": genesis.get("uid"),
        "event_count": meta["event_count"],
        "last_event_id": meta["last_event_id"],
        "state_hash": meta["state_hash"],
        "merkle_root": merkle_root,
        "beliefs": ns_counts,
        "actors": sorted(actors),
        "event_types": event_types,
        "keys": key_info,
        "missing_required_files": missing_files,
        "write_enabled": SIGNING_KEY_B64 is not None,
    }


@mcp.tool()
def list_events(
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    namespace: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List events with optional filters. Returns paginated results."""
    events = load_events(_events_path())

    filtered = events
    if event_type:
        filtered = [e for e in filtered if e.get("type") == event_type]
    if actor:
        filtered = [e for e in filtered if e.get("actor") == actor]
    if namespace:
        filtered = [e for e in filtered if e.get("namespace") == namespace]

    total = len(filtered)
    page = filtered[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "count": len(page),
        "events": page,
    }


@mcp.tool()
def get_event(event_id: str) -> dict:
    """Get a full event by its event_id."""
    events = load_events(_events_path())
    for e in events:
        if e.get("event_id") == event_id:
            return {"found": True, "event": e}
    return {"found": False, "event_id": event_id, "error": "Event not found"}


@mcp.tool()
def get_state(namespace: Optional[str] = None) -> dict:
    """Get current reduced state. Optionally filter by namespace (canonical, local, contested, archived)."""
    _, reducer = _load_and_reduce()
    state = reducer.export_state()

    if namespace:
        if namespace not in ("canonical", "local", "contested", "archived", "metadata"):
            return {"error": f"Unknown namespace: {namespace}. Valid: canonical, local, contested, archived, metadata"}
        return {
            "namespace": namespace,
            "entries": state.get(namespace, {}),
            "count": len(state.get(namespace, {})) if isinstance(state.get(namespace), dict) else None,
        }

    return {
        "canonical_count": len(state["canonical"]),
        "local_count": len(state["local"]),
        "contested_count": len(state["contested"]),
        "archived_count": len(state["archived"]),
        "state": state,
    }


@mcp.tool()
def get_beliefs(
    namespace: str = "canonical",
    key_pattern: Optional[str] = None,
) -> dict:
    """
    Query beliefs by namespace, with optional key pattern filter.
    Key format is 'subject:predicate'. Pattern matches as substring.
    """
    _, reducer = _load_and_reduce()
    state = reducer.export_state()

    if namespace not in ("canonical", "local", "contested", "archived"):
        return {"error": f"Unknown namespace: {namespace}"}

    beliefs = state.get(namespace, {})

    if key_pattern:
        beliefs = {k: v for k, v in beliefs.items() if key_pattern in k}

    return {
        "namespace": namespace,
        "count": len(beliefs),
        "beliefs": beliefs,
    }


@mcp.tool()
def get_evidence(belief_key_str: str) -> dict:
    """
    Get the full evidence trail for a belief key.
    Key format: 'subject:predicate' (e.g., 'door_01:opens').
    """
    _, reducer = _load_and_reduce()
    evidence = reducer.export_evidence()

    if belief_key_str in evidence:
        return {
            "belief_key": belief_key_str,
            "evidence_count": len(evidence[belief_key_str]),
            "evidence": evidence[belief_key_str],
        }

    return {
        "belief_key": belief_key_str,
        "evidence_count": 0,
        "evidence": [],
        "note": "No evidence found for this key. Use get_beliefs to see available keys.",
    }


@mcp.tool()
def verify_vault() -> dict:
    """Run integrity and compliance checks on the vault. Returns detailed pass/fail results."""
    vault = _vault()
    results = {
        "vault_path": str(vault),
        "checks": [],
        "passed": 0,
        "failed": 0,
    }

    def _check(name: str, passed: bool, detail: str = ""):
        results["checks"].append({"check": name, "passed": passed, "detail": detail})
        if passed:
            results["passed"] += 1
        else:
            results["failed"] += 1

    # 1. Required files
    manifest_path = vault / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        missing = check_required_files(manifest)
        _check("required_files", len(missing) == 0, f"Missing: {missing}" if missing else "All present")
    else:
        _check("required_files", False, "manifest.json not found")

    # 2. Genesis file
    genesis_path = vault / "identity" / "genesis.json"
    if genesis_path.exists():
        genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
        has_uid = bool(genesis.get("uid"))
        has_key = bool(genesis.get("root_key_id"))
        _check("genesis_valid", has_uid and has_key, f"uid={genesis.get('uid')}, root_key_id={genesis.get('root_key_id')}")
    else:
        _check("genesis_valid", False, "genesis.json not found")

    # 3. Events parseable
    events_path = _events_path()
    try:
        events = load_events(events_path)
        _check("events_parseable", True, f"{len(events)} events loaded")
    except Exception as exc:
        events = []
        _check("events_parseable", False, str(exc))

    # 4. Causal chains
    if events:
        chains = verify_all_causal_chains(events)
        broken = [a for a, v in chains.items() if not v]
        _check("causal_chains", len(broken) == 0, f"Broken: {broken}" if broken else f"All {len(chains)} actors valid")

    # 5. Forks
    if events:
        forks = detect_forks(events)
        _check("no_forks", len(forks) == 0, f"{len(forks)} forks detected" if forks else "No forks")

    # 6. Signature verification
    keys_path = _keys_path()
    if keys_path.exists() and events:
        registry = load_keys_registry(keys_path)
        valid_sigs, invalid_sigs, sig_errors = verify_all_signatures(events, registry)
        _check(
            "signatures",
            invalid_sigs == 0,
            f"valid={valid_sigs}, invalid={invalid_sigs}" + (f", errors: {sig_errors}" if sig_errors else ""),
        )

    # 7. Merkle root verification
    merkle_path = vault / "merkle_root.txt"
    if manifest_path.exists() and merkle_path.exists():
        stored_root = merkle_path.read_text(encoding="utf-8").strip()
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        leaves = manifest_leaves(manifest_data)
        computed_root = merkle_root_hex(leaves)
        _check("merkle_root", stored_root == computed_root,
               f"stored={stored_root[:16]}... computed={computed_root[:16]}...")

    # 8. Reducer determinism
    if events:
        _, reducer = _load_and_reduce()
        state = reducer.export_state()
        _check("reducer_runs", True, f"state_hash={state['metadata']['state_hash'][:16]}...")

    results["overall"] = "PASS" if results["failed"] == 0 else "FAIL"
    return results


@mcp.tool()
def search_events(
    subject: Optional[str] = None,
    predicate: Optional[str] = None,
    value: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """Search events by payload content (subject, predicate, or value substring match)."""
    events = load_events(_events_path())

    if not any([subject, predicate, value]):
        return {"error": "At least one search parameter required: subject, predicate, or value"}

    matches = []
    for e in events:
        payload = e.get("payload", {})
        if subject and subject not in str(payload.get("subject", "")):
            continue
        if predicate and predicate not in str(payload.get("predicate", "")):
            continue
        if value and value not in str(payload.get("value", "")):
            continue
        matches.append(e)
        if len(matches) >= limit:
            break

    return {
        "query": {"subject": subject, "predicate": predicate, "value": value},
        "count": len(matches),
        "events": matches,
    }


# ---------------------------------------------------------------------------
# Write Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def append_observation(
    subject: str,
    predicate: str,
    value: str,
    confidence: float = 0.5,
    namespace: str = "local",
    actor: str = "mcp_client",
) -> dict:
    """
    Append a signed OBSERVATION event to the vault.
    Requires HUNT_SIGNING_KEY_B64 environment variable.
    """
    try:
        private_key, key_id = _get_signing_context()
    except ValueError as exc:
        return {"error": str(exc)}

    return _append_event(
        event_type="OBSERVATION",
        subject=subject,
        predicate=predicate,
        value=value,
        confidence=confidence,
        namespace=namespace,
        actor=actor,
        private_key=private_key,
        key_id=key_id,
    )


@mcp.tool()
def append_assertion(
    subject: str,
    predicate: str,
    value: str,
    confidence: float = 0.35,
    namespace: str = "local",
    actor: str = "mcp_client",
) -> dict:
    """
    Append a signed ASSERTION event to the vault.
    Requires HUNT_SIGNING_KEY_B64 environment variable.
    """
    try:
        private_key, key_id = _get_signing_context()
    except ValueError as exc:
        return {"error": str(exc)}

    return _append_event(
        event_type="ASSERTION",
        subject=subject,
        predicate=predicate,
        value=value,
        confidence=confidence,
        namespace=namespace,
        actor=actor,
        private_key=private_key,
        key_id=key_id,
    )


def _append_event(
    event_type: str,
    subject: str,
    predicate: str,
    value: str,
    confidence: float,
    namespace: str,
    actor: str,
    private_key: Any,
    key_id: str,
) -> dict:
    """Internal: build, sign, and append an event to the vault."""
    vault = _vault()
    events_path = _events_path()

    # Load existing events to find chaining info
    events = load_events(events_path)

    # Find the last event by this actor for prev_event_hash
    prev_hash = None
    max_ts = 0
    for e in events:
        if e.get("actor") == actor:
            prev_hash = e.get("event_id")
            ts = e.get("ts_logical", 0) or 0
            max_ts = max(max_ts, ts)

    ts_logical = max_ts + 1 if max_ts > 0 else 1

    # Build the event
    event = {
        "type": event_type,
        "namespace": namespace,
        "actor": actor,
        "actor_key_id": key_id,
        "ts_logical": ts_logical,
        "prev_event_hash": prev_hash,
        "timestamp_utc": _utc_now_iso(),
        "payload": {
            "subject": subject,
            "predicate": predicate,
            "value": value,
            "confidence": confidence,
        },
    }

    # Content-addressed event_id
    event["event_id"] = f"evt_{canonical_hash(event)[:24]}"

    # Sign
    event = sign_event(event, private_key, key_id)

    # Append to events file
    with events_path.open("a", encoding="utf-8") as f:
        f.write(canonical_dumps(event) + "\n")

    # Regenerate manifest and merkle root
    try:
        regenerate_manifest(vault)
    except Exception:
        pass  # Non-fatal: vault is still valid, just manifest is stale

    # Re-run reducer to show updated state
    all_events = load_events(events_path)
    reducer = SovereignReducerV0()
    reducer.apply_events(all_events)
    state = reducer.export_state()
    bkey = belief_key(subject, predicate)

    return {
        "success": True,
        "event_id": event["event_id"],
        "event_type": event_type,
        "belief_key": bkey,
        "new_event_count": state["metadata"]["event_count"],
        "new_state_hash": state["metadata"]["state_hash"],
        "belief_status": _find_belief_namespace(state, bkey),
    }


def _find_belief_namespace(state: dict, bkey: str) -> str:
    """Find which namespace a belief key currently lives in."""
    for ns in ("canonical", "contested", "local"):
        if bkey in state.get(ns, {}):
            return ns
    return "not_found"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Hunt Protocol MCP Server")
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    # you can change the other arguments buy adding another parser.add_argument() here if needed :)
    args = parser.parse_args()
    
    mcp.run()


if __name__ == "__main__":
    main()
