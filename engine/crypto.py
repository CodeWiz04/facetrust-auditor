"""Encryption of embeddings at rest (AES-256-GCM).

An embedding is a biometric template, so it is never stored in plain form.
- Key comes from the environment (FACETRUST_EMBEDDING_KEY, base64, 32 bytes), never from code.
- A fresh random nonce is used for every encryption.
- `aad` (associated data, e.g. subject + image hash) is authenticated but not
  encrypted: a sealed blob cannot be moved to another record without detection.
- Blob layout: 1 version byte | 12-byte nonce | ciphertext+tag.
"""

import base64
import binascii
import os
from collections.abc import Mapping

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import EngineError

KEY_ENV = "FACETRUST_EMBEDDING_KEY"
_VERSION = b"\x01"
_NONCE_LEN = 12
_KEY_LEN = 32


def generate_key() -> str:
    """New random key, base64-encoded. Put it in .env; never commit it."""
    return base64.urlsafe_b64encode(os.urandom(_KEY_LEN)).decode("ascii")


def load_key(environ: Mapping | None = None) -> bytes:
    environ = os.environ if environ is None else environ
    text = environ.get(KEY_ENV)
    if not text:
        raise EngineError("CRY-KEY-INVALID", "key variable is not set")
    try:
        key = base64.urlsafe_b64decode(text.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise EngineError("CRY-KEY-INVALID", "key is not valid base64")
    if len(key) != _KEY_LEN:
        raise EngineError("CRY-KEY-INVALID", "key must decode to 32 bytes")
    return key  # the key value is never put in an error or a log


def _check_key(key) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_LEN:
        raise EngineError("CRY-KEY-INVALID", "key must be 32 bytes")


def seal_embedding(vector, key: bytes, aad: bytes) -> bytes:
    _check_key(key)
    arr = np.asarray(vector, dtype="<f4")
    if arr.ndim != 1 or arr.size == 0 or not np.all(np.isfinite(arr)):
        raise EngineError("EMB-INVALID-VECTOR", "cannot seal this vector")
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, arr.tobytes(), aad)
    return _VERSION + nonce + ciphertext


def open_embedding(blob: bytes, key: bytes, aad: bytes) -> np.ndarray:
    _check_key(key)
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 1 + _NONCE_LEN + 16 + 4:
        raise EngineError("CRY-DECRYPT-FAILED", "blob too short")
    blob = bytes(blob)
    if blob[:1] != _VERSION:
        raise EngineError("CRY-DECRYPT-FAILED", "unknown blob version")
    nonce = blob[1 : 1 + _NONCE_LEN]
    try:
        plain = AESGCM(bytes(key)).decrypt(nonce, blob[1 + _NONCE_LEN :], aad)
    except InvalidTag:
        raise EngineError("CRY-DECRYPT-FAILED", "authentication failed")
    if len(plain) % 4 != 0:
        raise EngineError("CRY-DECRYPT-FAILED", "bad payload length")
    return np.frombuffer(plain, dtype="<f4").astype(np.float64)