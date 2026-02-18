"""
Hunt Protocol — Sovereign Memory for AI Systems

L0 protocol modules for cryptographically signed, deterministic state management.
"""

__version__ = "0.1.1"

from .canonical_json import canonical_dumps, canonical_bytes, canonical_hash
from .signing import BackpackKeypair, sign_event, verify_event_signature
from .reducer import SovereignReducerV0
from .sync import load_events, write_events
