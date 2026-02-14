"""
reducer.py — Hunt Protocol L0 Deterministic Reducer (v0 hardened)

Core invariants:
  1. Events are immutable. Corrections are new events.
  2. Truth is not merged. Evidence is merged. Truth is recomputed.
  3. Deterministic: same events in same order -> byte-identical state hash.
  4. Provenance + confidence required for any claim affecting belief/state.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set
import copy

from .canonical_json import canonical_hash, canonical_dumps


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDUCER_NAME = "SovereignReducerV0"
REDUCER_VERSION = "0.2.0"
DEFAULT_CONFLICT_CONFIDENCE_THRESHOLD = 0.50
DEFAULT_OBSERVATION_CONFIDENCE = 0.50
DEFAULT_ASSERTION_CONFIDENCE = 0.35


# ---------------------------------------------------------------------------
# Evidence record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Evidence:
    event_id: str
    actor: str
    namespace: str
    timestamp_utc: Optional[str]
    value: Any
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "actor": self.actor,
            "namespace": self.namespace,
            "timestamp_utc": self.timestamp_utc,
            "value": self.value,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_NAMESPACES = frozenset({"canonical", "local", "contested", "archived"})


def belief_key(subject: str, predicate: str) -> str:
    return f"{subject}:{predicate}"


def _normalize_namespace(raw: Any) -> str:
    ns = str(raw or "local").strip().lower()
    return ns if ns in VALID_NAMESPACES else "local"


def _safe_float(val: Any, default: float) -> float:
    if val is None:
        return default
    try:
        f = float(val)
        return f if f == f else default
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Reducer
# ---------------------------------------------------------------------------

class SovereignReducerV0:
    """
    Four-namespace state model:
      canonical/  - attested institutional truth
      local/      - node-local observations (pending attestation)
      contested/  - conflicting high-confidence evidence
      archived/   - superseded canonical beliefs (audit trail)
    """

    def __init__(
        self,
        conflict_confidence_threshold: float = DEFAULT_CONFLICT_CONFIDENCE_THRESHOLD,
    ):
        self.conflict_confidence_threshold = float(conflict_confidence_threshold)

        self.state: Dict[str, Any] = {
            "canonical": {},
            "local": {},
            "contested": {},
            "archived": {},
            "metadata": {
                "last_event_id": None,
                "event_count": 0,
                "state_hash": None,
                "current_epoch": None,
                "reducer": {
                    "name": REDUCER_NAME,
                    "version": REDUCER_VERSION,
                    "conflict_confidence_threshold": self.conflict_confidence_threshold,
                },
            },
        }

        self._evidence: Dict[str, List[Evidence]] = {}
        self._ignored_types: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply_events(self, events: Iterable[Dict[str, Any]]) -> None:
        for event in events:
            self.apply_event(event)

    def apply_event(self, event: Dict[str, Any]) -> None:
        if not isinstance(event, dict):
            return

        e_type = event.get("type")
        event_id = event.get("event_id") or event.get("id") or "unknown_event"
        actor = str(event.get("actor") or "unknown")
        namespace = _normalize_namespace(event.get("namespace"))
        payload = event.get("payload") or {}

        if e_type == "OBSERVATION":
            self._handle_observation(event_id, actor, namespace, payload)
        elif e_type == "ASSERTION":
            self._handle_observation(
                event_id, actor, namespace, payload, is_assertion=True
            )
        elif e_type == "ATTESTATION":
            self._handle_attestation(event_id, actor, payload)
        elif e_type == "REDUCER_EPOCH":
            self._handle_reducer_epoch(event_id, payload)
        else:
            if e_type:
                self._ignored_types.add(str(e_type))

        self.state["metadata"]["last_event_id"] = event_id
        self.state["metadata"]["event_count"] += 1
        self.state["metadata"]["state_hash"] = self._compute_state_hash()

    def export_state(self) -> Dict[str, Any]:
        return {
            "canonical": self.state["canonical"],
            "local": self.state["local"],
            "contested": self.state["contested"],
            "archived": self.state["archived"],
            "metadata": self.state["metadata"],
        }

    def export_state_json(self) -> str:
        return canonical_dumps(self.export_state())

    def export_evidence(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            key: [ev.to_dict() for ev in evs]
            for key, evs in sorted(self._evidence.items())
        }

    # ------------------------------------------------------------------
    # State hash
    # ------------------------------------------------------------------

    def _compute_state_hash(self) -> str:
        hashable = {
            "canonical": self.state["canonical"],
            "local": self.state["local"],
            "contested": self.state["contested"],
            "archived": self.state["archived"],
            "metadata_partial": {
                "last_event_id": self.state["metadata"]["last_event_id"],
                "event_count": self.state["metadata"]["event_count"],
                "current_epoch": self.state["metadata"]["current_epoch"],
                "reducer": self.state["metadata"]["reducer"],
            },
        }
        return canonical_hash(hashable)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_observation(
        self,
        event_id: str,
        actor: str,
        namespace: str,
        payload: Dict[str, Any],
        is_assertion: bool = False,
    ) -> None:
        subject = payload.get("subject")
        predicate = payload.get("predicate")
        if not subject or not predicate:
            return

        key = belief_key(str(subject), str(predicate))
        value = payload.get("value")
        default_conf = DEFAULT_ASSERTION_CONFIDENCE if is_assertion else DEFAULT_OBSERVATION_CONFIDENCE
        confidence = _safe_float(payload.get("confidence"), default_conf)
        ts = payload.get("timestamp") or payload.get("timestamp_utc")

        ev = Evidence(
            event_id=event_id,
            actor=actor,
            namespace=namespace,
            timestamp_utc=str(ts) if ts is not None else None,
            value=value,
            confidence=confidence,
        )
        self._evidence.setdefault(key, []).append(ev)

        canonical_entry = self.state["canonical"].get(key)
        local_entry = self.state["local"].get(key)

        if (
            canonical_entry
            and canonical_entry.get("value") != value
            and confidence >= self.conflict_confidence_threshold
        ):
            self._mark_contested(key, reason="conflicts_with_canonical")
            return

        if local_entry and local_entry.get("value") != value:
            prev_conf = _safe_float(local_entry.get("confidence"), 0.0)
            if max(prev_conf, confidence) >= self.conflict_confidence_threshold:
                self._mark_contested(key, reason="conflicts_with_local")
                return

        if local_entry and local_entry.get("value") == value:
            existing_conf = _safe_float(local_entry.get("confidence"), 0.0)
            if confidence <= existing_conf:
                return

        self.state["local"][key] = {
            "value": value,
            "confidence": confidence,
            "provenance": event_id,
            "actor": actor,
            "timestamp": str(ts) if ts is not None else None,
            "evidence_count": len(self._evidence.get(key, [])),
        }

    def _handle_attestation(
        self, event_id: str, actor: str, payload: Dict[str, Any]
    ) -> None:
        subject = payload.get("subject")
        predicate = payload.get("predicate")
        if not subject or not predicate:
            return

        key = belief_key(str(subject), str(predicate))
        value = payload.get("value")
        target_event_id = payload.get("target_event_id")

        existing_canonical = self.state["canonical"].get(key)
        if existing_canonical is not None:
            archived_list = self.state["archived"].setdefault(key, [])
            archived_entry = copy.deepcopy(existing_canonical)
            archived_entry["superseded_by"] = event_id
            archived_list.append(archived_entry)

        self.state["canonical"][key] = {
            "value": value,
            "attested_by": payload.get("actor_key_id") or actor,
            "provenance": target_event_id or event_id,
            "attestation_event_id": event_id,
        }

        self.state["local"].pop(key, None)
        self.state["contested"].pop(key, None)

    def _handle_reducer_epoch(
        self, event_id: str, payload: Dict[str, Any]
    ) -> None:
        self.state["metadata"]["current_epoch"] = {
            "epoch_id": payload.get("epoch_id"),
            "reducer_hash": payload.get("reducer_hash"),
            "effective_from_event_id": payload.get("effective_from_event_id") or event_id,
            "ontology_versions": payload.get("ontology_versions"),
        }

    # ------------------------------------------------------------------
    # Contested belief handling
    # ------------------------------------------------------------------

    def _mark_contested(self, key: str, reason: str) -> None:
        all_evidence = self._evidence.get(key, [])

        by_value: Dict[str, list] = {}
        for ev in all_evidence:
            val_key = canonical_dumps(ev.value)
            by_value.setdefault(val_key, []).append(ev.to_dict())

        self.state["contested"][key] = {
            "status": "AWAITING_RESOLUTION",
            "reason": reason,
            "canonical_value": (
                self.state["canonical"].get(key, {}).get("value")
            ),
            "evidence_by_value": {
                k: entries for k, entries in sorted(by_value.items())
            },
            "total_evidence_count": len(all_evidence),
        }

        self.state["local"].pop(key, None)
