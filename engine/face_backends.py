

import numpy as np

from .errors import EngineError


class FaceRecognitionBackend:
    """dlib ResNet 128-d embeddings via the `face_recognition` package (CPU only)."""

    name = "dlib-resnet-128d"
    dim = 128

    def __init__(self, detector: str = "hog", num_jitters: int = 1):
        if detector not in ("hog", "cnn"):
            raise EngineError("EMB-BACKEND-ERROR", "detector must be 'hog' or 'cnn'")
        try:
            import dlib
            import face_recognition
        except Exception:  # ImportError, or a broken native build
            raise EngineError(
                "EMB-BACKEND-UNAVAILABLE",
                "face_recognition/dlib could not be imported",
            )
        self._fr = face_recognition
        self._detector = detector
        self._jitters = int(num_jitters)
        fr_version = getattr(face_recognition, "__version__", "unknown")
        dlib_version = getattr(dlib, "__version__", "unknown")
        self.version = f"face_recognition {fr_version} / dlib {dlib_version} / {detector}"

    def embed_faces(self, rgb: np.ndarray) -> list:
        locations = self._fr.face_locations(rgb, model=self._detector)
        if not locations:
            return []
        encodings = self._fr.face_encodings(
            rgb, known_face_locations=locations, num_jitters=self._jitters
        )
        return [np.asarray(e, dtype=np.float64) for e in encodings]