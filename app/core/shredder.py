"""Secure file shredding and media sanitization utility (FR-6).

Follows NIST SP 800-88 guidelines for clearing magnetic and flash storage
by overwriting sensitive biometric data with cryptographic random bytes and zeros
before unlinking the file from the filesystem.
"""

from __future__ import annotations

import os
from pathlib import Path

from engine.errors import EngineError

CHUNK_SIZE = 64 * 1024  # 64 KB chunks for memory-efficient I/O


def secure_shred_file(path: str | Path, passes: int = 2) -> bool:
    """Forensically overwrite and delete a file from the filesystem.

    Args:
        path: Path to the file to destroy.
        passes: Number of overwrite passes (default: 2, random bytes + zeros).

    Returns:
        True if the file was securely shredded and unlinked.

    Raises:
        EngineError: If the file exists but cannot be shredded or unlinked.
    """
    target = Path(path).resolve()
    if not target.exists():
        return False

    if not target.is_file():
        raise EngineError("DEL-VERIFY-FAILED", f"Target is not a regular file: {target}")

    try:
        file_size = target.stat().st_size
        if file_size > 0:
            with open(target, "r+b") as f:
                # Pass 1: Cryptographic pseudo-random bytes
                if passes >= 1:
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        n = min(remaining, CHUNK_SIZE)
                        f.write(os.urandom(n))
                        remaining -= n
                    f.flush()
                    os.fsync(f.fileno())

                # Pass 2: Zeroization (all 0x00 bytes)
                if passes >= 2:
                    f.seek(0)
                    zero_chunk = b"\x00" * CHUNK_SIZE
                    remaining = file_size
                    while remaining > 0:
                        n = min(remaining, CHUNK_SIZE)
                        f.write(zero_chunk[:n])
                        remaining -= n
                    f.flush()
                    os.fsync(f.fileno())

                # Truncate to 0 bytes before removal
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())

        # Unlink from directory
        target.unlink(missing_ok=True)
    except Exception as exc:
        raise EngineError("DEL-VERIFY-FAILED", f"Failed to securely shred file {target}: {exc}") from exc

    # Final verification: Ensure file no longer exists
    if target.exists():
        raise EngineError("DEL-VERIFY-FAILED", f"File still exists after shredding attempt: {target}")

    return True


def verify_file_deleted(path: str | Path) -> bool:
    """Verify that a given path no longer exists on disk."""
    return not Path(path).resolve().exists()
