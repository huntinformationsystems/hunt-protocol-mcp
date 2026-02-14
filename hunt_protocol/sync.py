"""
sync.py — Hunt Protocol L0 Multi-Device Sync Layer

Implements deterministic, offline-first, conflict-free synchronization
between multiple Hunt Protocol vaults.
"""

from __future__ import annotations
import base64
import datetime
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .canonical_json import canonical_bytes, canonical_dumps, canonical_hash
from .signing import (
    BackpackKeypair,
    load_keys_registry,
    load_private_key_b64,
    load_public_key_b64,
    resolve_public_key,
    sign_event,
    sign_manifest,
    verify_event_signature,
)
from .integrity import (
    canonical_json_bytes,
    merkle_root_hex,
    sha256_bytes,
    sha256_file,
    MANIFEST_EXCLUDE,
)
from .reducer import SovereignReducerV0
from .manifest import build_manifest, manifest_leaves


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Fork:
    actor_id: str
    prev_hash: Optional[str]
    event_a: Dict[str, Any]
    event_b: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "prev_hash": self.prev_hash,
            "event_a_id": self.event_a.get("event_id"),
            "event_b_id": self.event_b.get("event_id"),
        }


@dataclass
class MergeResult:
    merged_events: List[Dict[str, Any]]
    new_count: int
    conflicts: List[str] = field(default_factory=list)
    forks: List[Fork] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "merged_event_count": len(self.merged_events),
            "new_count": self.new_count,
            "conflict_count": len(self.conflicts),
            "conflicts": self.conflicts,
            "fork_count": len(self.forks),
            "forks": [f.to_dict() for f in self.forks],
        }


@dataclass
class SyncResult:
    success: bool
    events_merged: int
    new_state_hash: Optional[str]
    fencing_token: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    forks: List[Fork] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "events_merged": self.events_merged,
            "new_state_hash": self.new_state_hash,
            "fencing_token": self.fencing_token,
            "error_count": len(self.errors),
            "errors": self.errors,
            "fork_count": len(self.forks),
        }


@dataclass
class ImportResult:
    success: bool
    imported_count: int
    rejected_count: int
    new_state_hash: Optional[str]
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "imported_count": self.imported_count,
            "rejected_count": self.rejected_count,
            "new_state_hash": self.new_state_hash,
            "error_count": len(self.errors),
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Event log I/O
# ---------------------------------------------------------------------------

def load_events(path: Path) -> List[Dict[str, Any]]:
    events = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                events.append(json.loads(stripped))
            except json.JSONDecodeError:
                pass
    return events


def write_events(path: Path, events: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(canonical_dumps(event) + "\n")


def _event_content_hash(event: Dict[str, Any]) -> str:
    eid = event.get("event_id")
    if eid:
        return eid
    return canonical_hash(event)


# ---------------------------------------------------------------------------
# Core sync functions
# ---------------------------------------------------------------------------

def merge_event_logs(
    local_log_path: Path,
    remote_log_path: Path,
) -> MergeResult:
    local_events = load_events(local_log_path)
    remote_events = load_events(remote_log_path)

    seen: Set[str] = set()
    merged: List[Dict[str, Any]] = []
    new_count = 0

    for event in local_events:
        eid = _event_content_hash(event)
        if eid not in seen:
            seen.add(eid)
            merged.append(event)

    for event in remote_events:
        eid = _event_content_hash(event)
        if eid not in seen:
            seen.add(eid)
            merged.append(event)
            new_count += 1

    def sort_key(e: Dict[str, Any]) -> Tuple[str, str]:
        ts = e.get("timestamp_utc") or ""
        eid = e.get("event_id") or ""
        return (ts, eid)

    merged.sort(key=sort_key)

    forks = detect_forks(merged)
    conflicts = [f"Fork detected: actor={f.actor_id}, prev={f.prev_hash}" for f in forks]

    return MergeResult(
        merged_events=merged,
        new_count=new_count,
        conflicts=conflicts,
        forks=forks,
    )


def detect_forks(events: List[Dict[str, Any]]) -> List[Fork]:
    prev_map: Dict[Tuple[str, Optional[str]], List[Dict[str, Any]]] = {}
    for event in events:
        actor = event.get("actor")
        prev_hash = event.get("prev_event_hash")
        if actor is None:
            continue
        key = (actor, prev_hash)
        prev_map.setdefault(key, []).append(event)

    forks: List[Fork] = []
    for (actor, prev_hash), forked_events in sorted(
        prev_map.items(), key=lambda x: (x[0][0], x[0][1] or "")
    ):
        if len(forked_events) >= 2:
            for i in range(1, len(forked_events)):
                forks.append(Fork(
                    actor_id=actor,
                    prev_hash=prev_hash,
                    event_a=forked_events[0],
                    event_b=forked_events[i],
                ))
    return forks


def verify_causal_chain(events: List[Dict[str, Any]], actor_id: str) -> bool:
    actor_events = [e for e in events if e.get("actor") == actor_id]
    if not actor_events:
        return True
    first = actor_events[0]
    if first.get("prev_event_hash") is not None:
        return False
    for i in range(1, len(actor_events)):
        current = actor_events[i]
        expected_prev = actor_events[i - 1].get("event_id")
        if current.get("prev_event_hash") != expected_prev:
            return False
    return True


def get_all_actors(events: List[Dict[str, Any]]) -> Set[str]:
    return {e.get("actor") for e in events if e.get("actor")}


def verify_all_causal_chains(events: List[Dict[str, Any]]) -> Dict[str, bool]:
    actors = get_all_actors(events)
    return {actor: verify_causal_chain(events, actor) for actor in sorted(actors)}


def verify_all_signatures(
    events: List[Dict[str, Any]],
    keys_registry: Dict[str, Dict[str, Any]],
) -> Tuple[int, int, List[str]]:
    valid = 0
    invalid = 0
    errors: List[str] = []

    for event in events:
        sig = event.get("sig")
        kid = event.get("actor_key_id")
        eid = event.get("event_id", "unknown")

        if not sig:
            continue
        if not kid:
            invalid += 1
            errors.append(f"Event {eid}: missing actor_key_id")
            continue

        pk = resolve_public_key(kid, keys_registry)
        if pk is None:
            invalid += 1
            errors.append(f"Event {eid}: key {kid} not found in registry")
            continue

        if verify_event_signature(event, pk):
            valid += 1
        else:
            invalid += 1
            errors.append(f"Event {eid}: invalid signature")

    return valid, invalid, errors


# ---------------------------------------------------------------------------
# Manifest regeneration
# ---------------------------------------------------------------------------

def regenerate_manifest(backpack_path: Path) -> None:
    manifest = build_manifest(backpack_path, set(MANIFEST_EXCLUDE))
    leaves = manifest_leaves(manifest)
    root_hex = merkle_root_hex(leaves)

    (backpack_path / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    (backpack_path / "merkle_root.txt").write_text(root_hex + "\n", encoding="utf-8")
