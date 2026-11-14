import math
import os
import pytest

from app.core.crypto import (
    CryptoError,
    decrypt_bytes,
    decrypt_embedding,
    deserialize_vector,
    encrypt_bytes,
    encrypt_embedding,
    generate_biometric_key,
    get_biometric_key,
    secure_zero_memory,
    serialize_vector,
    set_active_key,
)


@pytest.fixture(autouse=True)
def setup_test_crypto_key():
    """Ensure a clean, isolated cryptographic test key is active for each test."""
    test_key = generate_biometric_key()
    set_active_key(test_key)
    yield test_key
    set_active_key(None)


# ---------- Key Management & Configuration ----------

def test_generate_biometric_key_is_valid():
    key = generate_biometric_key()
    assert isinstance(key, str)
    assert len(key) == 44  # 32 bytes base64-encoded is 44 characters


def test_missing_key_in_environment_raises_crypto_error(monkeypatch):
    set_active_key(None)
    monkeypatch.delenv("BIOMETRIC_ENCRYPTION_KEY", raising=False)
    with pytest.raises(CryptoError) as exc_info:
        get_biometric_key()
    assert exc_info.value.code == "CFG-UNKNOWN-KEY"


def test_invalid_key_format_raises_crypto_error():
    with pytest.raises(CryptoError) as exc_info:
        set_active_key("not-a-valid-base64-key")
    assert exc_info.value.code == "CFG-INVALID-TYPE"


def test_key_loaded_from_environment(monkeypatch):
    set_active_key(None)
    custom_key = generate_biometric_key()
    monkeypatch.setenv("BIOMETRIC_ENCRYPTION_KEY", custom_key)
    loaded = get_biometric_key()
    assert loaded == custom_key.encode("utf-8")


# ---------- Raw Bytes Encryption & Decryption (FR-2 Image Protection) ----------

def test_raw_bytes_encryption_roundtrip():
    sample_image_data = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF" + b"\x00" * 512
    ciphertext = encrypt_bytes(sample_image_data)
    assert ciphertext != sample_image_data
    assert len(ciphertext) > len(sample_image_data)

    decrypted = decrypt_bytes(ciphertext)
    assert decrypted == sample_image_data


def test_empty_bytes_rejected():
    with pytest.raises(CryptoError) as exc_info:
        encrypt_bytes(b"")
    assert exc_info.value.code == "FILE-CORRUPT"


def test_tampered_ciphertext_fails_integrity_check():
    sample_data = b"confidential_facial_features_and_raw_bytes"
    ciphertext = encrypt_bytes(sample_data)

    # Tamper with the payload (flip bits in the middle of ciphertext)
    tampered = bytearray(ciphertext)
    tampered[25] ^= 0xFF
    tampered_bytes = bytes(tampered)

    with pytest.raises(CryptoError) as exc_info:
        decrypt_bytes(tampered_bytes)
    assert exc_info.value.code == "DEL-VERIFY-FAILED"


def test_decryption_with_wrong_key_fails():
    sample_data = b"secret_data"
    key1 = generate_biometric_key().encode("utf-8")
    key2 = generate_biometric_key().encode("utf-8")

    ciphertext = encrypt_bytes(sample_data, key=key1)
    with pytest.raises(CryptoError) as exc_info:
        decrypt_bytes(ciphertext, key=key2)
    assert exc_info.value.code == "DEL-VERIFY-FAILED"


# ---------- Vector Serialization & Deserialization ----------

def test_vector_serialization_roundtrip_128d():
    vec = [0.123456 * i for i in range(128)]
    payload = serialize_vector(vec)
    assert len(payload) == 4 + 128 * 4  # 4-byte header + 512 bytes

    recovered = deserialize_vector(payload)
    assert len(recovered) == 128
    for orig, rec in zip(vec, recovered):
        assert math.isclose(orig, rec, rel_tol=1e-6)


def test_vector_serialization_roundtrip_512d():
    vec = [math.sin(i) for i in range(512)]
    payload = serialize_vector(vec)
    assert len(payload) == 4 + 512 * 4

    recovered = deserialize_vector(payload)
    assert len(recovered) == 512
    for orig, rec in zip(vec, recovered):
        assert math.isclose(orig, rec, rel_tol=1e-6)


@pytest.mark.parametrize(
    "bad_vector",
    [
        [],  # empty
        [1.0, 2.0, float("nan")],  # NaN
        [1.0, float("inf"), 3.0],  # Inf
        [1.0, "2.0", 3.0],  # non-numeric string
        [1.0, True, 3.0],  # boolean
    ],
)
def test_serialize_vector_rejects_invalid_values(bad_vector):
    with pytest.raises(CryptoError) as exc_info:
        serialize_vector(bad_vector)
    assert exc_info.value.code == "EMB-INVALID-VECTOR"


def test_deserialize_truncated_payload_rejected():
    with pytest.raises(CryptoError) as exc_info:
        deserialize_vector(b"\x00\x00\x00")
    assert exc_info.value.code == "EMB-INVALID-VECTOR"


def test_deserialize_length_mismatch_rejected():
    # Header says 10 elements (40 bytes needed), but we only pass 4 bytes header + 4 bytes
    fake_payload = b"\x00\x00\x00\x0a" + b"\x00\x00\x00\x00"
    with pytest.raises(CryptoError) as exc_info:
        deserialize_vector(fake_payload)
    assert exc_info.value.code == "EMB-INVALID-VECTOR"


# ---------- Full Embedding Encryption & Decryption (FR-2) ----------

def test_encrypt_decrypt_embedding_token():
    embedding = [0.05 * i - 0.2 for i in range(128)]
    token = encrypt_embedding(embedding)
    assert isinstance(token, str)
    assert len(token) > 0

    recovered = decrypt_embedding(token)
    assert len(recovered) == len(embedding)
    for orig, rec in zip(embedding, recovered):
        assert math.isclose(orig, rec, rel_tol=1e-6)


def test_secure_zero_memory():
    buf = bytearray(b"super_sensitive_biometric_key_bytes")
    assert any(b != 0 for b in buf)
    secure_zero_memory(buf)
    assert all(b == 0 for b in buf)
