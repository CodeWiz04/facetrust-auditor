"""Test doubles. NOT for production use: these do no real face recognition."""

import hashlib

import numpy as np


class FakeBackend:
    """Deterministic stand-in for a face library.

    - `faces` says how many faces to 'detect' (0, 1, 2...).
    - Each embedding is derived from the image content, so the same image
      always gives the same vector and different images give different ones.
    - `vector_override` lets a test return a deliberately broken vector.
    """

    name = "fake-embedder"
    version = "test-1.0"

    def __init__(self, faces=1, dim=128, vector_override=None, raises=None):
        self.faces = faces
        self.dim = dim
        self.vector_override = vector_override
        self.raises = raises

    def embed_faces(self, rgb):
        if self.raises is not None:
            raise self.raises
        digest = hashlib.sha256(np.ascontiguousarray(rgb).tobytes()).digest()
        seed = int.from_bytes(digest[:8], "little")
        out = []
        for i in range(self.faces):
            if self.vector_override is not None:
                out.append(self.vector_override)
            else:
                out.append(np.random.default_rng(seed + i).normal(size=self.dim))
        return out