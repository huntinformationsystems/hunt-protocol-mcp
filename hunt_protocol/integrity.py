"""
integrity.py — Hunt Protocol L0 Shared Integrity Primitives

Single source of truth for:
  - Canonical JSON serialization
  - SHA-256 file hashing
  - Merkle root computation
  - Path safety validation
"""

from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from typing import Any, List


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

def canonical_json_bytes(obj: Any) -> bytes:
    """JCS-like canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_str(obj: Any) -> str:
    return canonical_json_bytes(obj).decode("utf-8")


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------

def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """SHA-256 hex digest of file contents. Reads in chunks for large files."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

def merkle_root_hex(leaves: List[bytes]) -> str:
    """
    Binary Merkle tree over SHA-256.
    - Leaf hash = SHA-256(leaf_bytes)
    - Parent = SHA-256(left || right)
    - Odd leaf count: last node is duplicated (standard padding).
    - Empty tree: SHA-256 of empty bytes.
    """
    if not leaves:
        return hashlib.sha256(b"").hexdigest()

    level = [hashlib.sha256(leaf).digest() for leaf in leaves]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def is_safe_path(root: Path, rel_path: str) -> bool:
    if os.path.isabs(rel_path):
        return False
    parts = Path(rel_path).parts
    if ".." in parts:
        return False
    resolved = (root / rel_path).resolve()
    try:
        resolved.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def is_symlink_safe(path: Path, root: Path) -> bool:
    if not path.is_symlink():
        return True
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Spec constants
# ---------------------------------------------------------------------------

MANIFEST_EXCLUDE = frozenset({
    "manifest.json",
    "manifest.sig",
    "merkle_root.txt",
})

SPEC_REQUIRED_FILES = frozenset({
    "identity/genesis.json",
    "identity/keys.json",
    "events/events.ndjson",
    "policies/sync_contract.json",
    "policies/safety_policy.json",
    "policies/retention_policy.json",
    "manifest.json",
})

SUPPORTED_SPEC_VERSIONS = frozenset({"1.0"})
