"""Pydantic schemas for privacy-preserving deletion and deletion receipts (FR-6)."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SubjectDeletionRequest(BaseModel):
    """Irreversible privacy-preserving deletion request."""

    confirm: bool = Field(
        ...,
        description="Explicit confirmation required to permanently destroy biometric data",
    )
    reason: str | None = Field(
        default=None,
        description="Optional reason for audit records (must not contain PII)",
        max_length=200,
    )

    @field_validator("confirm")
    @classmethod
    def validate_confirmation(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("confirm must be True to execute permanent deletion")
        return v


class DeletionReceipt(BaseModel):
    """Cryptographic receipt proving complete data erasure without retaining PII."""

    subject_hash: str = Field(
        ...,
        description="SHA-256 pseudonym hash of the subject code",
    )
    status: str = Field(
        default="verified_deleted",
        description="Final verified status of data erasure",
    )
    images_shredded: int = Field(
        ...,
        description="Count of encrypted image files forensically shredded from disk",
    )
    embeddings_destroyed: int = Field(
        ...,
        description="Count of biometric embedding vectors permanently deleted",
    )
    tombstone_hash: str = Field(
        ...,
        description="Cryptographic SHA-256 hash of the audit deletion record",
    )
    deleted_at: datetime = Field(
        ...,
        description="Timestamp when erasure was verified",
    )
    statement: str = Field(
        default=(
            "All raw biometric files, derived embedding vectors, and identifiable personal "
            "records have been permanently destroyed in compliance with FR-6 privacy controls."
        )
    )

    model_config = ConfigDict(from_attributes=True)
