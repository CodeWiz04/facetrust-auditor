"""Cryptographic services for protecting biometric data at rest (FR-2).

Uses authenticated symmetric encryption (Fernet / AES-128-CBC + HMAC-SHA256)
to guarantee confidentiality and tamper-resistance for raw face images and
high-dimensional biometric embedding vectors.
"""

from __future__ import annotations

import base64
import math
import os
import struct
from typing import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken

from engine.errors import EngineError


class CryptoError(EngineError):
    """Domain-specific error for cryptographic failures with safe messages."""
    pass


_DEFAULT_ENV_KEY_VAR = "BIOMETRIC_ENCRYPTION_KEY"
_ACTIVE_IN_MEMORY_KEY: bytes | None = None


def generate_biometric_key() -> str:
    """Generate a cryptographically secure 32-byte URL-safe base64 Fernet key."""
    return Fernet.generate_key().decode("utf-8")


def set_active_key(key: str | bytes | None) -> None:
    """Set or clear an in-memory encryption key (primarily for isolated test fixtures)."""
    global _ACTIVE_IN_MEMORY_KEY
    if key is None:
        _ACTIVE_IN_MEMORY_KEY = None
        return
    if isinstance(key, str):
        key = key.encode("utf-8")
    _validate_key(key)
    _ACTIVE_IN_MEMORY_KEY = key


def _validate_key(key_bytes: bytes) -> None:
    """Verify that the key is a valid 32-byte url-safe base64 encoded string."""
    try:
        raw = base64.urlsafe_b64decode(key_bytes)
        if len(raw) != 32:
            raise CryptoError("CFG-INVALID-TYPE", "Biometric key raw length is not 32 bytes")
    except Exception as exc:
        raise CryptoError("CFG-INVALID-TYPE", f"Invalid biometric key format: {exc}") from exc


def get_biometric_key() -> bytes:
    """Resolve the active encryption key from in-memory cache or environment.

    Raises:
        CryptoError if no valid key is configured.
    """
    global _ACTIVE_IN_MEMORY_KEY
    if _ACTIVE_IN_MEMORY_KEY is not None:
        return _ACTIVE_IN_MEMORY_KEY

    env_val = os.getenv(_DEFAULT_ENV_KEY_VAR)
    if not env_val:
        raise CryptoError(
            "CFG-UNKNOWN-KEY",
            f"Missing required environment variable '{_DEFAULT_ENV_KEY_VAR}'",
        )
    key_bytes = env_val.strip().encode("utf-8")
    _validate_key(key_bytes)
    return key_bytes


def _get_cipher(key: bytes | None = None) -> Fernet:
    resolved_key = key if key is not None else get_biometric_key()
    try:
        return Fernet(resolved_key)
    except Exception as exc:
        raise CryptoError("CFG-INVALID-TYPE", f"Cannot initialize cipher: {exc}") from exc


def encrypt_bytes(data: bytes, key: bytes | None = None) -> bytes:
    """Encrypt raw binary data (e.g. image bytes) using authenticated encryption.

    Args:
        data: Plaintext bytes to protect.
        key: Optional explicit key; defaults to system biometric key.

    Returns:
        Fernet ciphertext bytes (includes version, timestamp, IV, ciphertext, HMAC).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise CryptoError("FILE-CORRUPT", "Data to encrypt must be binary bytes")
    if len(data) == 0:
        raise CryptoError("FILE-CORRUPT", "Cannot encrypt empty byte sequence")

    cipher = _get_cipher(key)
    return cipher.encrypt(bytes(data))


def decrypt_bytes(ciphertext: bytes, key: bytes | None = None) -> bytes:
    """Decrypt and authenticate ciphertext bytes.

    Args:
        ciphertext: Encrypted token to decrypt.
        key: Optional explicit key; defaults to system biometric key.

    Returns:
        Plaintext bytes.

    Raises:
        CryptoError: If token is malformed, key is incorrect, or ciphertext was tampered with.
    """
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
        raise CryptoError("FILE-CORRUPT", "Ciphertext must be non-empty bytes")

    cipher = _get_cipher(key)
    try:
        return cipher.decrypt(bytes(ciphertext))
    except (InvalidToken, InvalidSignature) as exc:
        raise CryptoError(
            "DEL-VERIFY-FAILED",
            "Decryption or HMAC verification failed. Data was tampered with or key is invalid.",
        ) from exc


def serialize_vector(vector: Sequence[float]) -> bytes:
    """Serialize a sequence of floats into a binary payload with dimension prefix.

    Format: [uint32 big-endian dimension N] + [N * 32-bit big-endian IEEE 754 floats].
    """
    if not isinstance(vector, (list, tuple)) and not hasattr(vector, "__len__"):
        raise CryptoError("EMB-INVALID-VECTOR", "Embedding vector must be a sequence of floats")

    dim = len(vector)
    if dim == 0:
        raise CryptoError("EMB-INVALID-VECTOR", "Embedding vector cannot be empty")

    for idx, val in enumerate(vector):
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            raise CryptoError("EMB-INVALID-VECTOR", f"Vector element at {idx} is not a float")
        if not math.isfinite(val):
            raise CryptoError("EMB-INVALID-VECTOR", f"Vector element at {idx} is not finite (NaN or Inf)")

    payload = bytearray(4 + dim * 4)
    struct.pack_into(">I", payload, 0, dim)
    struct.pack_into(f">{dim}f", payload, 4, *vector)
    return bytes(payload)


def deserialize_vector(payload: bytes) -> list[float]:
    """Deserialize a binary payload into a list of Python floats."""
    if len(payload) < 4:
        raise CryptoError("EMB-INVALID-VECTOR", "Payload too short to contain vector dimension")

    dim = struct.unpack_from(">I", payload, 0)[0]
    expected_len = 4 + dim * 4
    if len(payload) != expected_len:
        raise CryptoError(
            "EMB-INVALID-VECTOR",
            f"Payload size mismatch: expected {expected_len} bytes for dim={dim}, got {len(payload)}",
        )

    floats = struct.unpack_from(f">{dim}f", payload, 4)
    for val in floats:
        if not math.isfinite(val):
            raise CryptoError("EMB-INVALID-VECTOR", "Deserialized vector contains non-finite values")
    return list(floats)


def encrypt_embedding(vector: Sequence[float], key: bytes | None = None) -> str:
    """Serialize and encrypt a biometric embedding vector, returning a safe string token.

    Args:
        vector: List/array of floats representing the face embedding (e.g. 128d or 512d).
        key: Optional explicit key; defaults to system biometric key.

    Returns:
        URL-safe string ciphertext token.
    """
    serialized = serialize_vector(vector)
    encrypted = encrypt_bytes(serialized, key=key)
    return encrypted.decode("ascii")


def decrypt_embedding(token: str | bytes, key: bytes | None = None) -> list[float]:
    """Decrypt and deserialize a biometric embedding vector string token.

    Args:
        token: Ciphertext string or bytes.
        key: Optional explicit key; defaults to system biometric key.

    Returns:
        List of decoded floats.
    """
    if isinstance(token, str):
        ciphertext = token.encode("ascii")
    else:
        ciphertext = token

    decrypted_bytes = decrypt_bytes(ciphertext, key=key)
    return deserialize_vector(decrypted_bytes)


def secure_zero_memory(buffer: bytearray) -> None:
    """Best-effort in-memory wipe of sensitive mutable byte buffers."""
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
