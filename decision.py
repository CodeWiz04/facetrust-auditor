

import math
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from . import ENGINE_VERSION
from .errors import EngineError

STAGES = {"consent", "embedding", "threshold", "subgroup", "liveness", "deletion"}
STATUSES = {"completed", "rejected", "flagged"}
SEVERITIES = ("info", "low", "medium", "high", "critical")


class Timer:

    def __init__(self):
        self._start = time.perf_counter()

    def ms(self) -> float:
        return round((time.perf_counter() - self._start) * 1000, 3)


@dataclass(frozen=True)
class Decision:
    decision_id: str
    stage: str
    status: str
    outcome: str
    score: float | None
    threshold: float | None
    severity: str
    confidence: float | None
    rules_fired: tuple
    reasons: tuple
    model: str
    model_version: str
    engine_version: str
    config_hash: str
    input_ref: str
    latency_ms: float
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self):
        if self.stage not in STAGES:
            raise EngineError("ENG-INTERNAL", f"bad stage {self.stage!r}")
        if self.status not in STATUSES:
            raise EngineError("ENG-INTERNAL", f"bad status {self.status!r}")
        if self.severity not in SEVERITIES:
            raise EngineError("ENG-INTERNAL", f"bad severity {self.severity!r}")
        for name in ("score", "threshold", "confidence"):
            v = getattr(self, name)
            if v is not None and not math.isfinite(v):
                raise EngineError("ENG-INTERNAL", f"{name} is not finite")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise EngineError("ENG-INTERNAL", "confidence outside [0, 1]")
        # Explainability rules: never just "unsafe".
        if not self.reasons:
            raise EngineError("ENG-INTERNAL", "a decision must include reasons")
        if self.status in ("rejected", "flagged") and not self.rules_fired:
            raise EngineError("ENG-INTERNAL", "rejected/flagged needs a named rule")

    @classmethod
    def create(
        cls,
        *,
        stage,
        status,
        outcome,
        reasons,
        config_hash,
        input_ref,
        latency_ms,
        rules_fired=(),
        score=None,
        threshold=None,
        severity="info",
        confidence=None,
        model="n/a",
        model_version="n/a",
    ) -> "Decision":
        """Builder: generates the ID server-side and fills engine version."""
        return cls(
            decision_id=str(uuid.uuid4()),
            stage=stage,
            status=status,
            outcome=outcome,
            score=score,
            threshold=threshold,
            severity=severity,
            confidence=confidence,
            rules_fired=tuple(rules_fired),
            reasons=tuple(reasons),
            model=model,
            model_version=model_version,
            engine_version=ENGINE_VERSION,
            config_hash=config_hash,
            input_ref=input_ref,
            latency_ms=latency_ms,
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["rules_fired"] = list(self.rules_fired)  # JSON-friendly
        d["reasons"] = list(self.reasons)
        return d