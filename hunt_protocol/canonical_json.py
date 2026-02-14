"""
canonical_json.py — Hunt Protocol L0
Deterministic JSON canonicalization for content-addressed hashing.
Implements JCS-like canonical form (reference: RFC 8785).
"""

from __future__ import annotations
import hashlib
import json
from typing import Any


def canonical_dumps(obj: Any) -> str:
    """Return canonical JSON string with sorted keys and no whitespace."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    """Return canonical JSON as UTF-8 bytes."""
    return canonical_dumps(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj: Any) -> str:
    """Return SHA-256 hex digest of canonical JSON bytes."""
    return sha256_hex(canonical_bytes(obj))
