"""Secure file shredding and media sanitization utility (FR-6).

Delegates to engine.deletion forensic implementation conforming to NIST SP 800-88.
"""

from __future__ import annotations

from pathlib import Path

from engine.deletion import (
    CHUNK_SIZE,
    forensic_shred_file,
    verify_path_unlinked,
)


def secure_shred_file(path: str | Path, passes: int = 2) -> bool:
    """Forensically overwrite and delete a file from the filesystem."""
    return forensic_shred_file(path, passes=passes)


def verify_file_deleted(path: str | Path) -> bool:
    """Verify that a given path no longer exists on disk."""
    return verify_path_unlinked(path)


__all__ = ["CHUNK_SIZE", "secure_shred_file", "verify_file_deleted"]
