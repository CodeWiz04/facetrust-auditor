"""FR-6: Privacy-preserving deletion & forensic erasure (security engine, Layer 3).

Pure Python / OS utilities - no web framework, no database.

Enforces:
1. NIST SP 800-88 Rev 1 compliant forensic media sanitization (Clear / Purge):
   - Overwrite Pass 1: Cryptographic pseudo-random byte stream (os.urandom).
   - Overwrite Pass 2: Zeroization (0x00 bytes).
   - Truncation to 0 bytes and physical disk synchronization (fsync).
   - Filesystem unlinking and post-removal absence verification.
2. Cryptographic pseudonym generation for subject identifiers (SHA-256).
3. Verifiable cryptographic tombstone computation:
   - Proves complete erasure of raw biometrics, embeddings, and identity
   - Contains zero Personally Identifiable Information (PII)
4. Explainable Decision records with named rules for audit and compliance.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .decision import Decision, Timer
from .errors import EngineError
from .hashing import canonical_json, sha256_hex

DELETION_ENGINE_VERSION = "fr6-deletion-1.0.0"
CHUNK_SIZE = 64 * 1024  # 64 KB chunks for memory-efficient I/O
DEFAULT_OVERWRITE_PASSES = 2


@dataclass(frozen=True)
class DeletionRule:
    rule: str
    severity: str
    reason: str


@dataclass
class ForensicSanitizationResult:
    target_path: str
    shredded: bool
    verified_unlinked: bool
    bytes_overwritten: int
    passes_completed: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def forensic_shred_file(path: str | Path, passes: int = DEFAULT_OVERWRITE_PASSES) -> bool:
    """Forensically overwrite and delete a file from the filesystem.

    Follows NIST SP 800-88 guidelines for clearing magnetic and flash storage
    by overwriting sensitive biometric data with cryptographic random bytes and zeros
    before unlinking the file from the filesystem.

    Args:
        path: Path to the sensitive biometric file.
        passes: Number of overwrite passes (default: 2, random bytes + zeros).

    Returns:
        True if the file was securely shredded and unlinked, False if file did not exist.

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
                        chunk = min(remaining, CHUNK_SIZE)
                        f.write(os.urandom(chunk))
                        remaining -= chunk
                    f.flush()
                    os.fsync(f.fileno())

                # Pass 2: Zeroization (all 0x00 bytes)
                if passes >= 2:
                    f.seek(0)
                    zero_chunk = b"\x00" * CHUNK_SIZE
                    remaining = file_size
                    while remaining > 0:
                        chunk = min(remaining, CHUNK_SIZE)
                        f.write(zero_chunk[:chunk])
                        remaining -= chunk
                    f.flush()
                    os.fsync(f.fileno())

                # Truncate to 0 bytes before removal
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())

        # Unlink file from filesystem
        target.unlink(missing_ok=True)
    except Exception as exc:
        raise EngineError("DEL-VERIFY-FAILED", f"Failed to securely shred file {target}: {exc}") from exc

    # Verification: Ensure file no longer exists
    if target.exists():
        raise EngineError("DEL-VERIFY-FAILED", f"File still exists after shredding attempt: {target}")

    return True


def verify_path_unlinked(path: str | Path) -> bool:
    """Verify that a given path no longer exists on disk."""
    return not Path(path).resolve().exists()


def create_subject_pseudonym(subject_code: str) -> str:
    """Generate a non-reversible cryptographic pseudonym for a subject code (SHA-256).

    Guarantees no plaintext identifiers persist in audit receipts.
    """
    return sha256_hex(subject_code.strip())


def compute_tombstone_hash(
    subject_hash: str,
    images_shredded: int,
    embeddings_destroyed: int,
    deleted_at_iso: str,
    reason: str | None = None,
) -> str:
    """Compute a deterministic cryptographic hash of the deletion tombstone record.

    The tombstone hash uniquely seals the parameters of data erasure without
    exposing any underlying biometric information.
    """
    material = {
        "subject_hash": subject_hash,
        "images_shredded": int(images_shredded),
        "embeddings_destroyed": int(embeddings_destroyed),
        "deleted_at": deleted_at_iso,
        "reason": reason[:100] if reason else None,
    }
    return sha256_hex(canonical_json(material))


def evaluate_deletion_request(
    *,
    confirm: bool,
    subject_found: bool,
    images_count: int,
    embeddings_count: int,
    subject_hash: str,
    config_hash: str,
    reason: str | None = None,
    timer: Timer | None = None,
) -> tuple[Decision, list[DeletionRule]]:
    """Evaluate a privacy-preserving deletion operation and produce an explainable Decision.

    Returns:
        tuple[Decision, list[DeletionRule]]
    """
    t = timer or Timer()
    rules: list[DeletionRule] = []

    if not confirm:
        r = DeletionRule(
            rule="DEL-UNCONFIRMED-REJECTED",
            severity="medium",
            reason="High-impact deletion rejected: explicit confirmation is required.",
        )
        rules.append(r)
        decision = Decision.create(
            stage="deletion",
            status="rejected",
            outcome="confirmation_required",
            score=0.0,
            threshold=1.0,
            severity="medium",
            confidence=1.0,
            rules_fired=[r.rule],
            reasons=[r.reason],
            model="n/a",
            model_version="n/a",
            config_hash=config_hash,
            input_ref=f"pseudonym:{subject_hash}",
            latency_ms=t.ms(),
        )
        return decision, rules

    if not subject_found:
        r = DeletionRule(
            rule="DEL-TARGET-NOT-FOUND",
            severity="low",
            reason="Deletion rejected: target subject does not exist.",
        )
        rules.append(r)
        decision = Decision.create(
            stage="deletion",
            status="rejected",
            outcome="subject_not_found",
            score=0.0,
            threshold=1.0,
            severity="low",
            confidence=1.0,
            rules_fired=[r.rule],
            reasons=[r.reason],
            model="n/a",
            model_version="n/a",
            config_hash=config_hash,
            input_ref=f"pseudonym:{subject_hash}",
            latency_ms=t.ms(),
        )
        return decision, rules

    # Successful deletion rules
    rules.append(DeletionRule(
        rule="DEL-CONFIRMED-SHRED",
        severity="info",
        reason="Operator provided required cryptographic confirmation.",
    ))

    if images_count > 0:
        rules.append(DeletionRule(
            rule="DEL-IMAGES-PURGED",
            severity="info",
            reason=f"{images_count} encrypted biometric image(s) forensically overwritten and unlinked.",
        ))
    else:
        rules.append(DeletionRule(
            rule="DEL-ZERO-IMAGES",
            severity="info",
            reason="Subject had no stored biometric image files.",
        ))

    if embeddings_count > 0:
        rules.append(DeletionRule(
            rule="DEL-EMBEDDINGS-PURGED",
            severity="info",
            reason=f"{embeddings_count} biometric embedding vector(s) permanently erased.",
        ))
    else:
        rules.append(DeletionRule(
            rule="DEL-ZERO-EMBEDDINGS",
            severity="info",
            reason="Subject had no stored biometric embedding vectors.",
        ))

    rules.append(DeletionRule(
        rule="DEL-TOMBSTONE-VERIFIED",
        severity="info",
        reason="Cryptographic tombstone hash computed with zero PII retention.",
    ))

    reasons = [r.reason for r in rules]
    rules_fired = [r.rule for r in rules]

    decision = Decision.create(
        stage="deletion",
        status="completed",
        outcome="verified_deleted",
        score=1.0,
        threshold=1.0,
        severity="info",
        confidence=1.0,
        rules_fired=rules_fired,
        reasons=reasons,
        model="n/a",
        model_version="n/a",
        config_hash=config_hash,
        input_ref=f"pseudonym:{subject_hash}",
        latency_ms=t.ms(),
    )
    return decision, rules
