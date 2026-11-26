"""Pydantic schemas for privacy-preserving deletion and deletion receipts (FR-6)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SubjectDeletionRequest(BaseModel):
    """Irreversible privacy-preserving deletion request."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

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

    # FR-6 explainability & audit evidence
    rules_fired: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    decision: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class DeletionHistoryItem(BaseModel):
    """Row in the privacy deletion audit history table."""

    model_config = ConfigDict(protected_namespaces=())

    tombstone_hash: str
    subject_hash: str
    images_shredded: int
    embeddings_destroyed: int
    status: str
    deleted_at: datetime
    actor_role: str | None = None


class DeletionHistoryResponse(BaseModel):
    items: list[DeletionHistoryItem]
    total: int


class DeletionVerifyResponse(BaseModel):
    """Result of verifying a cryptographic deletion receipt against the audit log."""

    verified: bool
    tombstone_hash: str
    subject_hash: str | None = None
    audit_seq: int | None = None
    statement: str
