"""Face embedding extraction (FR-2).

The engine does not depend on any one face library. A *backend* turns an RGB
image into zero or more embedding vectors; this module decides what that
means (exactly one face required), validates and normalizes the vector, and
returns an explainable Decision. The raw vector is returned separately and is
NEVER placed in the Decision (so it cannot leak into logs or reports).
"""

from io import BytesIO
from typing import Protocol

import numpy as np
from PIL import Image

from .dataset_validator import ValidatedImage
from .decision import Decision, Timer
from .errors import EngineError


class EmbeddingBackend(Protocol):
    name: str      # e.g. "dlib-resnet-128d"
    version: str   # stored with every decision for reproducibility
    dim: int       # expected embedding length

    def embed_faces(self, rgb: np.ndarray) -> list:
        """Return one embedding per detected face (empty list = no face)."""
        ...


def l2_normalize(v) -> np.ndarray:
    """Return a unit-length float64 copy of a 1-D vector, or raise EMB-INVALID-VECTOR."""
    try:
        arr = np.asarray(v, dtype=np.float64)
    except (TypeError, ValueError):
        raise EngineError("EMB-INVALID-VECTOR", "not numeric")
    if arr.ndim != 1 or arr.size == 0:
        raise EngineError("EMB-INVALID-VECTOR", "must be a non-empty 1-D vector")
    if not np.all(np.isfinite(arr)):
        raise EngineError("EMB-INVALID-VECTOR", "contains NaN or infinity")
    with np.errstate(over="ignore"):
        norm = float(np.linalg.norm(arr))
    if norm == 0.0 or not np.isfinite(norm):
        raise EngineError("EMB-INVALID-VECTOR", "zero or non-finite norm")
    return arr / norm


def cosine_score(a, b) -> float:
    """Cosine similarity of two embeddings, always within [-1, 1]."""
    score = float(np.dot(l2_normalize(a), l2_normalize(b)))
    return max(-1.0, min(1.0, score))


def _decode_rgb(image: ValidatedImage) -> np.ndarray:
    try:
        with Image.open(BytesIO(image.png_bytes)) as img:
            return np.ascontiguousarray(np.asarray(img.convert("RGB"), dtype=np.uint8))
    except Exception:
        raise EngineError("FILE-CORRUPT", f"input_ref={image.input_ref} re-decode failed")


def extract_embedding(image: ValidatedImage, backend: EmbeddingBackend, config_hash: str):
    """Run the backend and return (Decision, embedding | None).

    Business rejections (no face, several faces, bad vector) are normal,
    auditable Decisions. A crashing backend raises EngineError, with only the
    exception TYPE recorded (messages could contain image data or paths).
    """
    timer = Timer()
    rgb = _decode_rgb(image)

    try:
        faces = backend.embed_faces(rgb)
    except EngineError:
        raise
    except Exception as exc:
        raise EngineError(
            "EMB-BACKEND-ERROR", f"input_ref={image.input_ref} {type(exc).__name__}"
        )

    common = dict(
        stage="embedding",
        config_hash=config_hash,
        input_ref=image.input_ref,
        model=backend.name,
        model_version=backend.version,
    )

    def reject(rule, reason, severity):
        return Decision.create(
            status="rejected",
            outcome="EMBEDDING_REJECTED",
            severity=severity,
            rules_fired=[rule],
            reasons=[reason],
            latency_ms=timer.ms(),
            **common,
        )

    count = len(faces)
    if count == 0:
        return reject("EMB-NO-FACE", "No face was detected in the image.", "low"), None
    if count > 1:
        return reject(
            "EMB-MULTI-FACE",
            f"{count} faces were detected; exactly one is required.",
            "low",
        ), None

    try:
        vector = l2_normalize(faces[0])
        if vector.shape[0] != backend.dim:
            raise EngineError("EMB-INVALID-VECTOR", "wrong dimension")
    except EngineError as err:
        return reject(
            err.code,
            f"The backend returned an invalid embedding ({err.detail}).",
            "high",
        ), None

    decision = Decision.create(
        status="completed",
        outcome="EMBEDDING_EXTRACTED",
        severity="info",
        reasons=[
            f"Exactly one face detected; {backend.dim}-dimensional embedding "
            f"extracted and L2-normalised using {backend.name}."
        ],
        latency_ms=timer.ms(),
        **common,
    )
    return decision, vector