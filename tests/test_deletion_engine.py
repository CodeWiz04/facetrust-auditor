"""FR-6 engine tests (pure Python / OS forensic layer - no server, no database).

Covers:
- NIST SP 800-88 compliant forensic overwriting and verified removal
- Cryptographic pseudonyms and tombstone hash calculation
- Explainable Decision creation with named rules and verifiable reasons
- Rejection on unconfirmed or missing deletion targets
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from engine.decision import Decision
from engine.deletion import (
    CHUNK_SIZE,
    compute_tombstone_hash,
    create_subject_pseudonym,
    evaluate_deletion_request,
    forensic_shred_file,
    verify_path_unlinked,
)
from engine.errors import EngineError


def test_forensic_shred_standard_file(tmp_path: Path):
    target = tmp_path / "face_enc_01.bin"
    payload = b"BIOMETRIC_DATA_SENSITIVE_" * 500
    target.write_bytes(payload)

    assert target.exists()
    assert target.stat().st_size == len(payload)

    ok = forensic_shred_file(target, passes=2)
    assert ok is True
    assert not target.exists()
    assert verify_path_unlinked(target) is True


def test_forensic_shred_empty_file(tmp_path: Path):
    target = tmp_path / "zero_bytes.bin"
    target.write_bytes(b"")

    assert target.exists()
    ok = forensic_shred_file(target)
    assert ok is True
    assert not target.exists()
    assert verify_path_unlinked(target) is True


def test_forensic_shred_large_chunked_file(tmp_path: Path):
    target = tmp_path / "large_biometric.enc"
    size = CHUNK_SIZE * 3 + 12345
    target.write_bytes(os.urandom(size))

    assert target.stat().st_size == size
    ok = forensic_shred_file(target, passes=2)
    assert ok is True
    assert not target.exists()
    assert verify_path_unlinked(target) is True


def test_forensic_shred_nonexistent_returns_false(tmp_path: Path):
    target = tmp_path / "phantom.enc"
    assert forensic_shred_file(target) is False
    assert verify_path_unlinked(target) is True


def test_forensic_shred_directory_fails(tmp_path: Path):
    directory = tmp_path / "biometrics_dir"
    directory.mkdir()

    with pytest.raises(EngineError) as exc_info:
        forensic_shred_file(directory)
    assert exc_info.value.code == "DEL-VERIFY-FAILED"


def test_subject_pseudonym_generation():
    code = "SUB-VOLUNTEER-42"
    h1 = create_subject_pseudonym(code)
    h2 = create_subject_pseudonym(code)
    h3 = create_subject_pseudonym("SUB-VOLUNTEER-43")

    assert len(h1) == 64
    assert h1 == h2  # Deterministic
    assert h1 != h3
    assert code not in h1  # Non-reversible
    assert all(c in "0123456789abcdef" for c in h1)


def test_tombstone_hash_deterministic():
    t1 = compute_tombstone_hash(
        subject_hash="a" * 64,
        images_shredded=3,
        embeddings_destroyed=3,
        deleted_at_iso="2026-11-26T12:00:00Z",
        reason="GDPR right to be forgotten",
    )
    t2 = compute_tombstone_hash(
        subject_hash="a" * 64,
        images_shredded=3,
        embeddings_destroyed=3,
        deleted_at_iso="2026-11-26T12:00:00Z",
        reason="GDPR right to be forgotten",
    )
    t3 = compute_tombstone_hash(
        subject_hash="a" * 64,
        images_shredded=4,  # different count
        embeddings_destroyed=3,
        deleted_at_iso="2026-11-26T12:00:00Z",
        reason="GDPR right to be forgotten",
    )

    assert len(t1) == 64
    assert t1 == t2
    assert t1 != t3


def test_decision_on_confirmed_deletion_with_artifacts():
    decision, rules = evaluate_deletion_request(
        confirm=True,
        subject_found=True,
        images_count=2,
        embeddings_count=2,
        subject_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        config_hash="c" * 64,
        reason="Subject withdrawn consent",
    )

    assert decision.stage == "deletion"
    assert decision.status == "completed"
    assert decision.outcome == "verified_deleted"
    assert decision.severity == "info"
    assert decision.confidence == 1.0

    rules_fired = list(decision.rules_fired)
    assert "DEL-CONFIRMED-SHRED" in rules_fired
    assert "DEL-IMAGES-PURGED" in rules_fired
    assert "DEL-EMBEDDINGS-PURGED" in rules_fired
    assert "DEL-TOMBSTONE-VERIFIED" in rules_fired
    assert any("2 encrypted biometric image(s)" in r for r in decision.reasons)


def test_decision_on_deletion_with_zero_artifacts():
    decision, rules = evaluate_deletion_request(
        confirm=True,
        subject_found=True,
        images_count=0,
        embeddings_count=0,
        subject_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        config_hash="c" * 64,
    )

    assert decision.status == "completed"
    rules_fired = list(decision.rules_fired)
    assert "DEL-ZERO-IMAGES" in rules_fired
    assert "DEL-ZERO-EMBEDDINGS" in rules_fired


def test_decision_rejected_when_unconfirmed():
    decision, rules = evaluate_deletion_request(
        confirm=False,
        subject_found=True,
        images_count=2,
        embeddings_count=2,
        subject_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        config_hash="c" * 64,
    )

    assert decision.stage == "deletion"
    assert decision.status == "rejected"
    assert decision.outcome == "confirmation_required"
    assert "DEL-UNCONFIRMED-REJECTED" in decision.rules_fired


def test_decision_rejected_when_subject_not_found():
    decision, rules = evaluate_deletion_request(
        confirm=True,
        subject_found=False,
        images_count=0,
        embeddings_count=0,
        subject_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        config_hash="c" * 64,
    )

    assert decision.stage == "deletion"
    assert decision.status == "rejected"
    assert decision.outcome == "subject_not_found"
    assert "DEL-TARGET-NOT-FOUND" in decision.rules_fired
