import os
from pathlib import Path
import pytest

from app.core.shredder import secure_shred_file, verify_file_deleted
from engine.errors import EngineError


def test_shred_existing_file(tmp_path: Path):
    target = tmp_path / "sensitive_face.enc"
    secret_bytes = b"CONFIDENTIAL_BIOMETRIC_DATA_" * 1000
    target.write_bytes(secret_bytes)

    assert target.exists()
    assert target.stat().st_size == len(secret_bytes)

    success = secure_shred_file(target, passes=2)
    assert success is True
    assert not target.exists()
    assert verify_file_deleted(target) is True


def test_shred_empty_file(tmp_path: Path):
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")

    assert target.exists()
    success = secure_shred_file(target)
    assert success is True
    assert not target.exists()


def test_shred_nonexistent_file_returns_false(tmp_path: Path):
    target = tmp_path / "never_existed.enc"
    assert secure_shred_file(target) is False
    assert verify_file_deleted(target) is True


def test_shred_multi_chunk_file(tmp_path: Path):
    # Test file larger than CHUNK_SIZE (64KB)
    target = tmp_path / "large_biometric_blob.enc"
    large_payload = os.urandom(150 * 1024)  # 150 KB
    target.write_bytes(large_payload)

    assert target.stat().st_size == 150 * 1024
    success = secure_shred_file(target, passes=2)
    assert success is True
    assert not target.exists()


def test_shred_directory_raises_error(tmp_path: Path):
    sub_dir = tmp_path / "test_dir"
    sub_dir.mkdir()

    with pytest.raises(EngineError) as exc_info:
        secure_shred_file(sub_dir)
    assert exc_info.value.code == "DEL-VERIFY-FAILED"
