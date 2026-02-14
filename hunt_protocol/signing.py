"""
signing.py — Hunt Protocol L0 Cryptographic Signing Layer

Implements Ed25519 keypair generation, event signing/verification,
manifest signing/verification, and key serialization.
"""

from __future__ import annotations
import base64
import datetime
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature

from .canonical_json import canonical_bytes, canonical_dumps, canonical_hash


# ---------------------------------------------------------------------------
# Key ID derivation
# ---------------------------------------------------------------------------

def key_id_from_public_bytes(pub_bytes: bytes) -> str:
    digest = hashlib.sha256(pub_bytes).hexdigest()
    return f"bp1_{digest[:16]}"


# ---------------------------------------------------------------------------
# Keypair management
# ---------------------------------------------------------------------------

@dataclass
class BackpackKeypair:
    """An Ed25519 keypair with Backpack-specific metadata."""
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    key_id: str
    public_key_b64: str

    @classmethod
    def generate(cls) -> "BackpackKeypair":
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        pub_bytes = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
        kid = key_id_from_public_bytes(pub_bytes)
        return cls(private_key=sk, public_key=pk, key_id=kid, public_key_b64=pub_b64)

    def private_key_b64(self) -> str:
        raw = self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return base64.b64encode(raw).decode("ascii")

    def to_keys_entry(
        self,
        roles: Optional[List[str]] = None,
        scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": "Ed25519",
            "public_key_b64": self.public_key_b64,
            "roles": roles or ["root", "attestation"],
            "scopes": scopes or ["all"],
            "status": "active",
            "created_at_utc": _utc_now_iso(),
        }


def load_private_key_b64(b64_str: str) -> Ed25519PrivateKey:
    raw = base64.b64decode(b64_str)
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key_b64(b64_str: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64_str)
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Event signing
# ---------------------------------------------------------------------------

def sign_event(
    event: Dict[str, Any],
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> Dict[str, Any]:
    event = dict(event)
    event["actor_key_id"] = key_id
    event.pop("sig", None)
    payload_bytes = canonical_bytes(event)
    sig_bytes = private_key.sign(payload_bytes)
    event["sig"] = base64.b64encode(sig_bytes).decode("ascii")
    return event


def verify_event_signature(
    event: Dict[str, Any],
    public_key: Ed25519PublicKey,
) -> bool:
    sig_b64 = event.get("sig")
    if not sig_b64:
        return False
    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return False
    check_event = {k: v for k, v in event.items() if k != "sig"}
    payload_bytes = canonical_bytes(check_event)
    try:
        public_key.verify(sig_bytes, payload_bytes)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Manifest signing
# ---------------------------------------------------------------------------

def sign_manifest(
    manifest_path: Path,
    merkle_root_path: Path,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> Dict[str, Any]:
    merkle_root = merkle_root_path.read_text(encoding="utf-8").strip()
    signable = {
        "merkle_root": merkle_root,
        "key_id": key_id,
        "spec_version": "1.0",
        "signed_at_utc": _utc_now_iso(),
    }
    signable_bytes = canonical_bytes(signable)
    sig_bytes = private_key.sign(signable_bytes)
    return {
        "merkle_root": merkle_root,
        "key_id": key_id,
        "spec_version": "1.0",
        "signed_at_utc": signable["signed_at_utc"],
        "sig": base64.b64encode(sig_bytes).decode("ascii"),
    }


def verify_manifest_signature(
    sig_record: Dict[str, Any],
    public_key: Ed25519PublicKey,
    expected_merkle_root: Optional[str] = None,
) -> bool:
    sig_b64 = sig_record.get("sig")
    if not sig_b64:
        return False
    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return False
    check = {k: v for k, v in sig_record.items() if k != "sig"}
    payload_bytes = canonical_bytes(check)
    try:
        public_key.verify(sig_bytes, payload_bytes)
    except InvalidSignature:
        return False
    if expected_merkle_root and sig_record.get("merkle_root") != expected_merkle_root:
        return False
    return True


# ---------------------------------------------------------------------------
# Key registry helpers
# ---------------------------------------------------------------------------

def load_keys_registry(keys_path: Path) -> Dict[str, Dict[str, Any]]:
    data = json.loads(keys_path.read_text(encoding="utf-8"))
    registry = {}
    for entry in data.get("keys", []):
        kid = entry.get("key_id")
        if kid:
            registry[kid] = entry
    return registry


def resolve_public_key(
    key_id: str,
    keys_registry: Dict[str, Dict[str, Any]],
) -> Optional[Ed25519PublicKey]:
    entry = keys_registry.get(key_id)
    if not entry:
        return None
    if entry.get("status") == "revoked":
        return None
    pub_b64 = entry.get("public_key_b64")
    if not pub_b64:
        return None
    try:
        return load_public_key_b64(pub_b64)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
