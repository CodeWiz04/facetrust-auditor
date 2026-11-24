"""SQLAlchemy ORM models for evaluation runs, threshold curves, bias audits, and liveness."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.time import utcnow
from app.db.base import Base


class EvaluationType(str, enum.Enum):
    THRESHOLD = "threshold"
    BIAS_AUDIT = "bias_audit"
    LIVENESS = "liveness"


class EvaluationRun(Base):
    """An execution of a threshold tuning, subgroup bias audit, or liveness test session (FR-3, FR-4, FR-5)."""

    __tablename__ = "evaluation_runs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    run_type: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False
    )  # threshold, bias_audit, liveness
    model_name: Mapped[str] = mapped_column(
        String(64), nullable=False, default="dlib-resnet-128d"
    )
    model_version: Mapped[str] = mapped_column(
        String(64), nullable=False, default="1.0"
    )
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    operating_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary_metrics_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )

    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )

    results: Mapped[list["EvaluationResult"]] = relationship(
        "EvaluationResult",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="EvaluationResult.created_at.asc()",
    )


class EvaluationResult(Base):
    """Granular data points (curve steps, subgroup slices, sample decisions) from an evaluation run."""

    __tablename__ = "evaluation_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evaluation_runs.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    category: Mapped[str] = mapped_column(
        String(64), index=True, nullable=False
    )  # curve_point, subgroup, liveness_sample
    item_key: Mapped[str] = mapped_column(
        String(128), index=True, nullable=False
    )  # e.g., "0.55", "female_20s", sample_hash
    metrics_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )
    decision_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )

    run: Mapped["EvaluationRun"] = relationship(
        "EvaluationRun", back_populates="results"
    )
