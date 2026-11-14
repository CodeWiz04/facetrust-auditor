"""SQLAlchemy ORM models for subjects, face images, and biometric embeddings."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.time import utcnow
from app.db.base import Base


class ConsentStatus(str, enum.Enum):
    GRANTED = "granted"
    WITHDRAWN = "withdrawn"
    REVOKED = "revoked"


class Subject(Base):
    """A human subject who provided face samples with verifiable consent (FR-1, FR-6)."""

    __tablename__ = "subjects"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    subject_code: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    consent_status: Mapped[str] = mapped_column(
        String(20), default=ConsentStatus.GRANTED.value, nullable=False, index=True
    )
    consent_date: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # ISO 8601 (YYYY-MM-DD)
    purpose: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # evaluation, threshold_tuning, bias_audit
    group: Mapped[str] = mapped_column(
        String(64), default="undisclosed", nullable=False, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )

    images: Mapped[list["SubjectImage"]] = relationship(
        "SubjectImage",
        back_populates="subject",
        cascade="all, delete-orphan",
        order_by="SubjectImage.created_at.desc()",
    )
    embeddings: Mapped[list["BiometricEmbedding"]] = relationship(
        "BiometricEmbedding",
        back_populates="subject",
        cascade="all, delete-orphan",
    )


class SubjectImage(Base):
    """An uploaded face image, stored encrypted at rest (FR-1, FR-2)."""

    __tablename__ = "subject_images"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    subject_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    input_hash: Mapped[str] = mapped_column(
        String(71), nullable=False, index=True
    )  # sha256:... of raw upload
    clean_hash: Mapped[str] = mapped_column(
        String(71), nullable=False, index=True
    )  # sha256:... of normalized PNG
    storage_path: Mapped[str] = mapped_column(
        String(512), nullable=False
    )  # relative path to ciphertext .enc file
    width: Mapped[int] = mapped_column(Integer, nullable=False)
    height: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_type: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # png | jpeg

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )

    subject: Mapped["Subject"] = relationship("Subject", back_populates="images")
    embeddings: Mapped[list["BiometricEmbedding"]] = relationship(
        "BiometricEmbedding",
        back_populates="image",
        cascade="all, delete-orphan",
    )


class BiometricEmbedding(Base):
    """Encrypted face embedding vector associated with an image and subject (FR-2)."""

    __tablename__ = "biometric_embeddings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    image_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("subject_images.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subject_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    model_name: Mapped[str] = mapped_column(
        String(64), nullable=False, default="facenet"
    )
    model_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0"
    )
    encrypted_embedding: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # Fernet encrypted token
    vector_dim: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )

    image: Mapped["SubjectImage"] = relationship(
        "SubjectImage", back_populates="embeddings"
    )
    subject: Mapped["Subject"] = relationship(
        "Subject", back_populates="embeddings"
    )
