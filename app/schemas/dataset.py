"""Pydantic schemas for subject consent, image uploads, and biometric metadata."""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SUBJECT_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9 _/-]{1,40}$")
ALLOWED_PURPOSES = {"evaluation", "threshold_tuning", "bias_audit"}


class SubjectCreate(BaseModel):
    """Schema for registering a new subject with explicit consent (FR-1)."""

    subject_code: str = Field(
        ...,
        description="Unique anonymous identifier for the subject (e.g. sub_001)",
        min_length=3,
        max_length=64,
    )
    consent_given: bool = Field(
        ...,
        description="Must be explicitly True to process subject data",
    )
    consent_date: str = Field(
        ...,
        description="ISO 8601 date when consent was given (YYYY-MM-DD)",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    purpose: Literal["evaluation", "threshold_tuning", "bias_audit"] = Field(
        ...,
        description="Permitted research/audit purpose under informed consent",
    )
    group: str = Field(
        default="undisclosed",
        description="Self-reported demographic subgroup label",
        max_length=40,
    )

    @field_validator("subject_code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if not SUBJECT_CODE_RE.match(v):
            raise ValueError("subject_code format invalid; only alphanumeric, dash, and underscore allowed")
        return v

    @field_validator("consent_given")
    @classmethod
    def validate_consent(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("consent_given must be explicitly True")
        return v

    @field_validator("consent_date")
    @classmethod
    def validate_date(cls, v: str) -> str:
        try:
            parsed = date.fromisoformat(v)
        except ValueError as exc:
            raise ValueError("consent_date is not a real ISO date") from exc
        if parsed > date.today():
            raise ValueError("consent_date cannot be in the future")
        return v

    @field_validator("group")
    @classmethod
    def validate_group(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            return "undisclosed"
        if not GROUP_RE.match(v):
            raise ValueError("group label format invalid")
        return v


class ConsentWithdrawRequest(BaseModel):
    """Request to withdraw/revoke a subject's consent (FR-6)."""

    reason: str | None = Field(
        default=None,
        description="Optional reason for withdrawal (never store sensitive PII)",
        max_length=200,
    )


class SubjectResponse(BaseModel):
    """Sanitized subject details for auditor/operator review."""

    id: str
    subject_code: str
    consent_status: str
    consent_date: str
    purpose: str
    group: str
    created_at: datetime
    updated_at: datetime
    image_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class SubjectListResponse(BaseModel):
    """Paginated subject listing."""

    items: list[SubjectResponse]
    total: int


class ImageUploadResponse(BaseModel):
    """Summary of validated, normalized, and encrypted image."""

    id: str
    subject_id: str
    original_filename: str
    input_hash: str
    clean_hash: str
    width: int
    height: int
    detected_type: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ImageListResponse(BaseModel):
    """List of images associated with a subject."""

    items: list[ImageUploadResponse]
    total: int


class EmbeddingMetadataResponse(BaseModel):
    """Metadata describing an encrypted face embedding vector."""

    id: str
    image_id: str
    subject_id: str
    model_name: str
    model_version: str
    vector_dim: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
