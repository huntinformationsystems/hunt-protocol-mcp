"""
rekey.py — Hunt Protocol L0 Key Rotation Protocol

Handles key revocation and promotion without losing the chain of evidence.
"""

from __future__ import annotations
import copy
import json
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical_json import canonical_bytes, canonical_dumps, canonical_hash
from .signing import (
    BackpackKeypair,
    key_id_from_public_bytes,
    load_keys_registry,
    load_public_key_b64,
    sign_event,
    sign_manifest,
    verify_event_signature,
    _utc_now_iso,
)


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------

def _next_logical_ts(events_path: Path, actor: str) -> int:
    max_ts = 0
    if events_path.is_file():
        with events_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if e.get("actor") == actor:
                        ts = e.get("ts_logical", 0) or 0
                        max_ts = max(max_ts, ts)
                except json.JSONDecodeError:
                    continue
    return max_ts + 1


def _last_event_id_for_actor(events_path: Path, actor: str) -> Optional[str]:
    last_id = None
    if events_path.is_file():
        with events_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if e.get("actor") == actor:
                        last_id = e.get("event_id")
                except json.JSONDecodeError:
                    continue
    return last_id


def build_rotation_event(
    event_type: str,
    payload: Dict[str, Any],
    actor: str,
    events_path: Path,
) -> Dict[str, Any]:
    ts_logical = _next_logical_ts(events_path, actor)
    prev_hash = _last_event_id_for_actor(events_path, actor)
    now = _utc_now_iso()

    event = {
        "event_id": None,
        "type": event_type,
        "namespace": "canonical",
        "actor": actor,
        "ts_logical": ts_logical,
        "prev_event_hash": prev_hash,
        "timestamp_utc": now,
        "payload": payload,
    }

    hashable = {k: v for k, v in event.items() if k not in ("event_id", "sig")}
    event["event_id"] = f"evt_{canonical_hash(hashable)[:24]}"
    return event


def append_event(events_path: Path, event: Dict[str, Any]) -> None:
    line = canonical_dumps(event) + "\n"
    with events_path.open("a", encoding="utf-8") as f:
        f.write(line)


# ---------------------------------------------------------------------------
# Core rotation procedure
# ---------------------------------------------------------------------------

class RotationResult:
    def __init__(self):
        self.success: bool = False
        self.revocation_event_id: Optional[str] = None
        self.promotion_event_id: Optional[str] = None
        self.new_key_id: Optional[str] = None
        self.old_key_id: Optional[str] = None
        self.signed_by: Optional[str] = None
        self.errors: List[str] = []
        self.warnings: List[str] = []


def rotate_key(
    backpack_root: Path,
    compromised_key_id: str,
    signing_private_key: Ed25519PrivateKey,
    signing_key_id: str,
    new_keypair: Optional[BackpackKeypair] = None,
    new_key_roles: Optional[List[str]] = None,
    trust_boundary_event_id: Optional[str] = None,
    actor: str = "key_rotation_authority",
) -> RotationResult:
    result = RotationResult()
    result.old_key_id = compromised_key_id

    if signing_key_id == compromised_key_id:
        result.errors.append(
            "SECURITY VIOLATION: Cannot sign rotation with the compromised key."
        )
        return result

    keys_path = backpack_root / "identity" / "keys.json"
    events_path = backpack_root / "events" / "events.ndjson"

    if not keys_path.is_file():
        result.errors.append("identity/keys.json not found")
        return result
    if not events_path.is_file():
        result.errors.append("events/events.ndjson not found")
        return result

    keys_data = json.loads(keys_path.read_text(encoding="utf-8"))
    registry = {}
    for entry in keys_data.get("keys", []):
        registry[entry.get("key_id")] = entry

    if compromised_key_id not in registry:
        result.errors.append(f"Compromised key '{compromised_key_id}' not found in keys.json")
        return result

    if signing_key_id not in registry:
        result.errors.append(f"Signing key '{signing_key_id}' not found in keys.json")
        return result

    if registry[signing_key_id].get("status") == "revoked":
        result.errors.append(f"Signing key '{signing_key_id}' is revoked.")
        return result

    if new_keypair is None:
        new_keypair = BackpackKeypair.generate()

    result.new_key_id = new_keypair.key_id

    if new_key_roles is None:
        new_key_roles = registry[compromised_key_id].get("roles", ["root"])

    revocation_payload = {
        "revoked_key_id": compromised_key_id,
        "reason": "key_compromise",
        "trust_boundary_event_id": trust_boundary_event_id,
        "revoked_at_utc": _utc_now_iso(),
    }
    revocation_event = build_rotation_event("KEY_REVOCATION", revocation_payload, actor, events_path)
    revocation_event = sign_event(revocation_event, signing_private_key, signing_key_id)
    append_event(events_path, revocation_event)
    result.revocation_event_id = revocation_event["event_id"]

    promotion_payload = {
        "new_key_id": new_keypair.key_id,
        "new_public_key_b64": new_keypair.public_key_b64,
        "algorithm": "Ed25519",
        "roles": new_key_roles,
        "promoted_by": signing_key_id,
        "replaces_key_id": compromised_key_id,
        "promoted_at_utc": _utc_now_iso(),
    }
    promotion_event = build_rotation_event("KEY_PROMOTION", promotion_payload, actor, events_path)
    promotion_event = sign_event(promotion_event, signing_private_key, signing_key_id)
    append_event(events_path, promotion_event)
    result.promotion_event_id = promotion_event["event_id"]

    for entry in keys_data["keys"]:
        if entry.get("key_id") == compromised_key_id:
            entry["status"] = "revoked"
            entry["revoked_at_utc"] = _utc_now_iso()
            entry["revocation_event_id"] = result.revocation_event_id
            break

    new_key_entry = new_keypair.to_keys_entry(
        roles=new_key_roles,
        scopes=registry[compromised_key_id].get("scopes", ["all"]),
    )
    new_key_entry["promotion_event_id"] = result.promotion_event_id
    keys_data["keys"].append(new_key_entry)

    keys_data.setdefault("revocations", []).append({
        "key_id": compromised_key_id,
        "revocation_event_id": result.revocation_event_id,
        "revoked_at_utc": _utc_now_iso(),
    })

    keys_path.write_text(
        json.dumps(keys_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    result.signed_by = signing_key_id
    result.success = True
    return result
