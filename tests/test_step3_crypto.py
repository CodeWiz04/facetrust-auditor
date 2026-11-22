import numpy as np
import pytest

from engine.crypto import (
    KEY_ENV,
    generate_key,
    load_key,
    open_embedding,
    seal_embedding,
)
from engine.errors import EngineError

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
AAD = b"subj_001|sha256:abc"
VEC = np.random.default_rng(0).normal(size=128)


def code_of(fn, *args):
    with pytest.raises(EngineError) as ei:
        fn(*args)
    return ei.value.code


# ---------- round trip ----------
def test_roundtrip_returns_same_vector_within_float32_precision():
    blob = seal_embedding(VEC, KEY, AAD)
    out = open_embedding(blob, KEY, AAD)
    assert out.shape == VEC.shape
    assert np.allclose(out, VEC, atol=1e-6)


def test_ciphertext_does_not_contain_plaintext_bytes():
    plain = np.asarray(VEC, dtype="<f4").tobytes()
    blob = seal_embedding(VEC, KEY, AAD)
    assert plain not in blob and plain[:16] not in blob


def test_same_vector_sealed_twice_gives_different_blobs():
    assert seal_embedding(VEC, KEY, AAD) != seal_embedding(VEC, KEY, AAD)


# ---------- tampering / wrong inputs ----------
def test_wrong_key_fails():
    blob = seal_embedding(VEC, KEY, AAD)
    assert code_of(open_embedding, blob, OTHER_KEY, AAD) == "CRY-DECRYPT-FAILED"


def test_wrong_aad_fails_so_blob_cannot_be_moved_to_another_record():
    blob = seal_embedding(VEC, KEY, AAD)
    assert code_of(open_embedding, blob, KEY, b"subj_002|sha256:abc") == "CRY-DECRYPT-FAILED"


@pytest.mark.parametrize("position", [0, 5, 20, -1])
def test_any_flipped_byte_is_detected(position):
    blob = bytearray(seal_embedding(VEC, KEY, AAD))
    blob[position] ^= 0x01
    assert code_of(open_embedding, bytes(blob), KEY, AAD) == "CRY-DECRYPT-FAILED"


@pytest.mark.parametrize("blob", [b"", b"\x01", b"\x01" + bytes(20), None, "text"])
def test_short_or_malformed_blob_fails_safely(blob):
    assert code_of(open_embedding, blob, KEY, AAD) == "CRY-DECRYPT-FAILED"


def test_truncated_blob_fails():
    blob = seal_embedding(VEC, KEY, AAD)
    assert code_of(open_embedding, blob[:-5], KEY, AAD) == "CRY-DECRYPT-FAILED"


@pytest.mark.parametrize("bad", [np.full(4, np.nan), np.zeros((2, 2)), []])
def test_seal_rejects_invalid_vectors(bad):
    assert code_of(seal_embedding, bad, KEY, AAD) == "EMB-INVALID-VECTOR"


@pytest.mark.parametrize("bad_key", [b"short", None, "a" * 32, b"x" * 33])
def test_bad_key_type_or_length_rejected(bad_key):
    assert code_of(seal_embedding, VEC, bad_key, AAD) == "CRY-KEY-INVALID"
    assert code_of(open_embedding, b"\x01" + bytes(60), bad_key, AAD) == "CRY-KEY-INVALID"


# ---------- key loading ----------
def test_generated_key_loads_and_works():
    key = load_key({KEY_ENV: generate_key()})
    assert len(key) == 32
    assert np.allclose(open_embedding(seal_embedding(VEC, key, AAD), key, AAD), VEC, atol=1e-6)


def test_generated_keys_are_unique():
    assert generate_key() != generate_key()


@pytest.mark.parametrize("env", [{}, {KEY_ENV: ""}, {KEY_ENV: "not base64 !!"}, {KEY_ENV: "c2hvcnQ="}])
def test_missing_or_invalid_key_variable_rejected(env):
    assert code_of(load_key, env) == "CRY-KEY-INVALID"


def test_key_value_never_appears_in_error_detail():
    secret = "c2hvcnQ="  # base64 of "short": valid base64, wrong length
    with pytest.raises(EngineError) as ei:
        load_key({KEY_ENV: secret})
    assert secret not in (ei.value.detail or "")
    assert secret not in str(ei.value.to_dict())