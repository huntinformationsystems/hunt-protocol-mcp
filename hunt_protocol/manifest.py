"""
manifest.py — Hunt Protocol L0 Manifest + Merkle Root Generator
"""

from __future__ import annotations
import datetime
import json
import sys
from pathlib import Path
from typing import Dict, List, Set

from .integrity import (
    canonical_json_bytes,
    is_symlink_safe,
    merkle_root_hex,
    sha256_file,
    MANIFEST_EXCLUDE,
    SPEC_REQUIRED_FILES,
)


def iter_backpack_files(
    root: Path,
    exclude: Set[str],
) -> List[Dict]:
    root = root.resolve()
    files = []

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if rel in exclude:
            continue
        if p.is_symlink() and not is_symlink_safe(p, root):
            continue
        files.append({
            "path": rel,
            "sha256": sha256_file(p),
            "size": p.stat().st_size,
        })

    files.sort(key=lambda x: x["path"])
    return files


def build_manifest(root: Path, exclude: Set[str]) -> Dict:
    files = iter_backpack_files(root, exclude)
    manifest = {
        "backpack_spec_version": "1.0",
        "manifest_version": "manifest.v0",
        "created_at_utc": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "file_count": len(files),
        "files": files,
    }
    return manifest


def manifest_leaves(manifest: Dict) -> List[bytes]:
    return [canonical_json_bytes(f) for f in manifest["files"]]


def check_required_files(manifest: Dict) -> List[str]:
    present = {f["path"] for f in manifest["files"]}
    missing = []
    for req in sorted(SPEC_REQUIRED_FILES):
        if req == "manifest.json":
            continue
        if req not in present:
            missing.append(req)
    return missing
