"""Seed SYNTHETIC consented subjects + encrypted embeddings for the FR-3 demo.

No real faces are involved: each "subject" is a random identity vector and
each "sample" is that vector plus noise. This is the safe sample data for
demonstrating threshold tuning (T1/T2) on any laptop, without dlib.

"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.crypto import encrypt_embedding, set_active_key  # noqa: E402
from app.db.session import SessionLocal, init_db  # noqa: E402
from app.models.dataset import (  # noqa: E402
    BiometricEmbedding,
    ConsentStatus,
    Subject,
    SubjectImage,
)

PREFIX = "DEMO-FR3-"
MODEL_NAME = "synthetic-demo-128d"
MODEL_VERSION = "1.0.0"
GROUPS = ("group_a", "group_b", "group_c")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--subjects", type=int, default=40)
    p.add_argument("--per-subject", type=int, default=5)
    p.add_argument("--dim", type=int, default=128)
    p.add_argument("--noise", type=float, default=0.45,
                   help="per-sample noise (0.2 = easy, 0.9 = hard)")
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--reset", action="store_true", help="delete existing demo subjects and exit")
    args = p.parse_args()

    if not (2 <= args.subjects <= 500 and 1 <= args.per_subject <= 20
            and 8 <= args.dim <= 1024 and 0.0 < args.noise <= 5.0):
        print("arguments out of range", file=sys.stderr)
        return 2

    settings = get_settings()
    if settings.biometric_encryption_key:
        set_active_key(settings.biometric_encryption_key)
    init_db()

    with SessionLocal() as db:
        ids = list(db.scalars(select(Subject.id).where(Subject.subject_code.like(f"{PREFIX}%"))))
        if ids:
            db.execute(delete(Subject).where(Subject.id.in_(ids)))
            db.commit()
            print(f"removed {len(ids)} previous demo subjects")
        if args.reset:
            return 0

        rng = np.random.default_rng(args.seed)
        for s in range(args.subjects):
            code = f"{PREFIX}{s:04d}"
            sub = Subject(
                subject_code=code,
                consent_status=ConsentStatus.GRANTED.value,
                consent_date="2026-11-01",
                purpose="threshold_tuning",
                group=GROUPS[s % len(GROUPS)],
            )
            db.add(sub)
            db.flush()
            identity = rng.normal(size=args.dim)
            for k in range(args.per_subject):
                img = SubjectImage(
                    subject_id=sub.id,
                    original_filename=f"synthetic_{k}.png",
                    input_hash=f"sha256:synthetic-{code}-{k}",
                    clean_hash=f"sha256:synthetic-clean-{code}-{k}",
                    storage_path="synthetic/none.enc",   # no image file exists
                    width=150,
                    height=150,
                    detected_type="png",
                )
                db.add(img)
                db.flush()
                vector = identity + rng.normal(scale=args.noise, size=args.dim)
                db.add(BiometricEmbedding(
                    image_id=img.id,
                    subject_id=sub.id,
                    model_name=MODEL_NAME,
                    model_version=MODEL_VERSION,
                    encrypted_embedding=encrypt_embedding(vector.tolist()),
                    vector_dim=args.dim,
                ))
        db.commit()

    n = args.subjects * args.per_subject
    print(f"seeded {args.subjects} synthetic subjects / {n} encrypted embeddings")
    print(f"model_name = {MODEL_NAME!r}  (use this in POST /api/v1/threshold/evaluate)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())