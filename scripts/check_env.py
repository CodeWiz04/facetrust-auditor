"""Quick environment check. Run from the repo root:  python scripts/check_env.py

Tells you which engine dependencies work on this machine, so you find out
about a dlib problem in minutes instead of in week 3.
"""

import importlib
import sys

REQUIRED = ["numpy", "PIL", "cryptography", "cv2", "pandas"]
OPTIONAL = ["face_recognition", "dlib"]


def check(name):
    try:
        module = importlib.import_module(name)
        return True, getattr(module, "__version__", "ok")
    except Exception as exc:  # broken native builds raise more than ImportError
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    print(f"Python {sys.version.split()[0]}")
    if sys.version_info >= (3, 13):
        print("  note: dlib/face_recognition usually have no wheels for Python 3.13+; "
              "3.10-3.12 is safest.")
    failed = False
    print("\nRequired:")
    for name in REQUIRED:
        ok, info = check(name)
        failed |= not ok
        print(f"  [{'OK' if ok else 'FAIL'}] {name}: {info}")
    print("\nOptional (real face backend):")
    for name in OPTIONAL:
        ok, info = check(name)
        print(f"  [{'OK' if ok else 'MISSING'}] {name}: {info}")
    ok, _ = check("face_recognition")
    if ok:
        from engine.face_backends import FaceRecognitionBackend
        import numpy as np
        backend = FaceRecognitionBackend()
        faces = backend.embed_faces(np.full((200, 200, 3), 128, dtype=np.uint8))
        print(f"\nSmoke test: blank image -> {len(faces)} faces (expected 0). "
              f"Backend: {backend.name}, {backend.version}")
    else:
        print("\nReal backend unavailable: the engine and tests still run with the fake backend.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())