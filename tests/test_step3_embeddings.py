import json
import sys
from io import BytesIO

import numpy as np
import pytest
from PIL import Image

from engine.dataset_validator import validate_image
from engine.embeddings import cosine_score, extract_embedding, l2_normalize
from engine.errors import EngineError
from engine.face_backends import FaceRecognitionBackend
from engine.hashing import config_hash
from engine.policy import load_default_config
from tests.fakes import FakeBackend

CFG = load_default_config()
CH = config_hash(CFG)


def make_validated(color=(120, 80, 40)):
    buf = BytesIO()
    Image.new("RGB", (128, 128), color).save(buf, format="PNG")
    return validate_image(buf.getvalue(), CFG["limits"], "a.png")


# ---------- l2_normalize ----------
def test_l2_normalize_gives_unit_length_and_keeps_direction():
    out = l2_normalize([3.0, 4.0])
    assert np.isclose(np.linalg.norm(out), 1.0)
    assert np.allclose(out, [0.6, 0.8])


def test_l2_normalize_accepts_lists_and_does_not_mutate_input():
    src = np.array([2.0, 0.0])
    l2_normalize(src)
    assert list(src) == [2.0, 0.0]


@pytest.mark.parametrize(
    "bad",
    [
        np.zeros(4),
        [float("nan"), 1.0],
        [float("inf"), 1.0],
        [[1.0, 2.0], [3.0, 4.0]],
        [],
        "not a vector",
        None,
        [1e200, 1e200],
    ],
)
def test_l2_normalize_rejects_invalid_vectors(bad):
    with pytest.raises(EngineError) as ei:
        l2_normalize(bad)
    assert ei.value.code == "EMB-INVALID-VECTOR"


# ---------- cosine_score ----------
def test_cosine_identical_opposite_orthogonal():
    assert cosine_score([1, 2, 3], [1, 2, 3]) == pytest.approx(1.0)
    assert cosine_score([1, 2, 3], [-1, -2, -3]) == pytest.approx(-1.0)
    assert cosine_score([1, 0], [0, 1]) == pytest.approx(0.0)


def test_cosine_is_scale_invariant():
    assert cosine_score([1, 2, 3], [10, 20, 30]) == pytest.approx(1.0)


@pytest.mark.parametrize("seed", range(10))
def test_cosine_always_within_bounds(seed):
    rng = np.random.default_rng(seed)
    assert -1.0 <= cosine_score(rng.normal(size=128), rng.normal(size=128)) <= 1.0


def test_cosine_rejects_zero_vector():
    with pytest.raises(EngineError):
        cosine_score(np.zeros(3), [1, 2, 3])


# ---------- extract_embedding: success ----------
def test_one_face_completes_with_unit_vector_and_full_evidence():
    img = make_validated()
    d, vec = extract_embedding(img, FakeBackend(faces=1), CH)
    assert d.status == "completed" and d.outcome == "EMBEDDING_EXTRACTED"
    assert vec.shape == (128,) and np.isclose(np.linalg.norm(vec), 1.0)
    assert d.model == "fake-embedder" and d.model_version == "test-1.0"
    assert d.config_hash == CH and d.input_ref == img.input_ref
    assert d.rules_fired == () and d.reasons and d.latency_ms >= 0


def test_decision_never_contains_the_vector():
    d, vec = extract_embedding(make_validated(), FakeBackend(), CH)
    as_dict = d.to_dict()
    json.dumps(as_dict)  # must serialize without any numpy array inside
    assert not any(isinstance(v, np.ndarray) for v in as_dict.values())
    assert "vector" not in as_dict and "embedding" not in as_dict
    assert all(len(str(v)) < 200 for v in as_dict.values())  # no 128-number payload


def test_same_image_gives_same_embedding():
    a = extract_embedding(make_validated(), FakeBackend(), CH)[1]
    b = extract_embedding(make_validated(), FakeBackend(), CH)[1]
    assert cosine_score(a, b) == pytest.approx(1.0)


def test_different_images_give_different_embeddings():
    a = extract_embedding(make_validated((10, 10, 10)), FakeBackend(), CH)[1]
    b = extract_embedding(make_validated((200, 30, 90)), FakeBackend(), CH)[1]
    assert cosine_score(a, b) < 0.5


# ---------- extract_embedding: rejections ----------
def test_no_face_is_rejected_with_named_rule():
    d, vec = extract_embedding(make_validated(), FakeBackend(faces=0), CH)
    assert vec is None and d.status == "rejected"
    assert d.rules_fired == ("EMB-NO-FACE",) and d.reasons


def test_multiple_faces_rejected_and_count_reported():
    d, vec = extract_embedding(make_validated(), FakeBackend(faces=2), CH)
    assert vec is None and d.rules_fired == ("EMB-MULTI-FACE",)
    assert "2 faces" in d.reasons[0]


@pytest.mark.parametrize(
    "override",
    [
        np.zeros(128),
        np.full(128, np.nan),
        np.full(128, np.inf),
        np.ones(64),            # wrong dimension
        np.ones((2, 64)),       # wrong shape
    ],
)
def test_invalid_backend_vectors_are_rejected_not_passed_on(override):
    d, vec = extract_embedding(
        make_validated(), FakeBackend(faces=1, vector_override=override), CH
    )
    assert vec is None and d.status == "rejected"
    assert d.rules_fired == ("EMB-INVALID-VECTOR",) and d.severity == "high"


def test_backend_crash_becomes_safe_error_without_leaking_message():
    boom = RuntimeError("secret path /home/user/private.png")
    with pytest.raises(EngineError) as ei:
        extract_embedding(make_validated(), FakeBackend(raises=boom), CH)
    assert ei.value.code == "EMB-BACKEND-ERROR"
    assert "secret" not in json.dumps(ei.value.to_dict())
    assert "secret" not in ei.value.detail and "RuntimeError" in ei.value.detail


# ---------- real backend ----------
def test_real_backend_missing_gives_stable_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "face_recognition", None)  # forces ImportError
    with pytest.raises(EngineError) as ei:
        FaceRecognitionBackend()
    assert ei.value.code == "EMB-BACKEND-UNAVAILABLE"


def test_real_backend_rejects_unknown_detector():
    with pytest.raises(EngineError):
        FaceRecognitionBackend(detector="magic")


def test_real_backend_smoke_blank_image_has_no_face():
    pytest.importorskip("face_recognition")
    backend = FaceRecognitionBackend()
    d, vec = extract_embedding(make_validated(), backend, CH)
    assert d.rules_fired == ("EMB-NO-FACE",) and vec is None
    assert d.model == "dlib-resnet-128d"