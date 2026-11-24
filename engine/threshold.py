"""FR-3: Threshold tuning (security engine, Layer 3)..

Decision rule used everywhere in this module:

    ACCEPT (same person)  if  cosine_score >= threshold
    REJECT                otherwise

Definitions (verification / 1:1 matching):

    FAR (false accept rate) = impostor pairs accepted / impostor pairs
    FRR (false reject rate) = genuine pairs rejected  / genuine pairs

What the module produces for one evaluation:

* exact FAR/FRR (with Wilson 95% confidence intervals) at the *active* policy
  threshold - this is what the system does today (T1);
* the *recommended* threshold: the lowest threshold whose empirical FAR is
  <= target FAR (lowest = fewest false rejects for that security level);
* the Equal Error Rate (EER) and its threshold (interpolated);
* a FAR/FRR/TPR curve over a threshold grid for ROC/DET plots (T2);
* named rules (never just "unsafe") explaining any warning, plus a
  confidence value that drops when there are too few pairs to support the
  target FAR statistically ("rule of three": with zero observed false
  accepts in n trials the 95% upper bound on FAR is about 3/n).

"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Mapping, Sequence

import numpy as np

from .decision import Decision, Timer
from .embeddings import l2_normalize
from .errors import EngineError

THRESHOLD_ENGINE_VERSION = "fr3-threshold-1.0.0"

# ---- Guard rails (not admin-tunable on purpose) ---------------------------
MIN_GENUINE_PAIRS = 30          # below this, FRR estimates are very noisy
ZERO_ERROR_FACTOR = 3.0         # rule of three -> need >= 3/target_far impostor pairs
HIGH_FRR_WARNING = 0.20         # recommended threshold rejects > 20% of genuine users
DEFAULT_MAX_IMPOSTOR_PAIRS = 200_000
MAX_EMBEDDINGS = 20_000         # hard cap on vectors loaded for one run
DEFAULT_SAMPLE_SEED = 20_26     # fixed -> sampled runs are reproducible
CURVE_STEPS_MIN, CURVE_STEPS_MAX = 10, 500
TARGET_FAR_MIN, TARGET_FAR_MAX = 0.0001, 0.5   # same range as policy.TUNABLES
THRESHOLD_DECIMALS = 4
_BLOCK = 512                    # rows per block for the similarity matrix

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PairScores:
    genuine: np.ndarray            # sorted ascending
    impostor: np.ndarray           # sorted ascending
    impostor_total: int            # all possible impostor pairs
    impostor_sampled: bool         # True if `impostor` is a seeded sample
    sample_seed: int | None
    subjects: int
    embeddings: int
    dim: int


@dataclass(frozen=True)
class OperatingPoint:
    threshold: float
    far: float
    frr: float
    far_ci95: tuple[float, float]
    frr_ci95: tuple[float, float]
    false_accepts: int
    false_rejects: int
    genuine_pairs: int
    impostor_pairs: int

    def to_dict(self) -> dict:
        d = asdict(self)
        d["far_ci95"] = list(self.far_ci95)
        d["frr_ci95"] = list(self.frr_ci95)
        return d


@dataclass(frozen=True)
class FiredRule:
    rule: str
    severity: str
    reason: str


@dataclass
class ThresholdReport:
    target_far: float
    active: OperatingPoint
    recommended: OperatingPoint
    target_met: bool
    target_band: tuple[float, float]
    eer: float
    eer_threshold: float
    curve: list[dict]
    genuine_summary: dict
    impostor_summary: dict
    d_prime: float | None
    min_impostor_pairs_for_target: int
    min_genuine_pairs: int
    subjects: int
    embeddings: int
    dim: int
    genuine_pairs: int
    impostor_pairs: int
    impostor_pairs_total: int
    impostor_sampled: bool
    sample_seed: int | None
    rules: list[FiredRule] = field(default_factory=list)
    recommended_action: str = ""
    engine_version: str = THRESHOLD_ENGINE_VERSION

    def to_dict(self) -> dict:
        return {
            "target_far": self.target_far,
            "target_met": self.target_met,
            "target_band": list(self.target_band),
            "active": self.active.to_dict(),
            "recommended": self.recommended.to_dict(),
            "eer": self.eer,
            "eer_threshold": self.eer_threshold,
            "genuine_summary": self.genuine_summary,
            "impostor_summary": self.impostor_summary,
            "d_prime": self.d_prime,
            "min_impostor_pairs_for_target": self.min_impostor_pairs_for_target,
            "min_genuine_pairs": self.min_genuine_pairs,
            "subjects": self.subjects,
            "embeddings": self.embeddings,
            "dim": self.dim,
            "genuine_pairs": self.genuine_pairs,
            "impostor_pairs": self.impostor_pairs,
            "impostor_pairs_total": self.impostor_pairs_total,
            "impostor_sampled": self.impostor_sampled,
            "sample_seed": self.sample_seed,
            "rules": [asdict(r) for r in self.rules],
            "recommended_action": self.recommended_action,
            "engine_version": self.engine_version,
        }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def validate_target_far(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EngineError("CFG-INVALID-TYPE", "target_far must be a number")
    value = float(value)
    if not math.isfinite(value) or not TARGET_FAR_MIN <= value <= TARGET_FAR_MAX:
        raise EngineError(
            "CFG-OUT-OF-RANGE", f"target_far allowed=[{TARGET_FAR_MIN},{TARGET_FAR_MAX}]"
        )
    return value


def validate_threshold(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EngineError("CFG-INVALID-TYPE", "threshold must be a number")
    value = float(value)
    if not math.isfinite(value) or not -1.0 <= value <= 1.0:
        raise EngineError("CFG-OUT-OF-RANGE", "threshold allowed=[-1,1]")
    return value


def validate_steps(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EngineError("CFG-INVALID-TYPE", "curve_steps must be an integer")
    if not CURVE_STEPS_MIN <= value <= CURVE_STEPS_MAX:
        raise EngineError(
            "CFG-OUT-OF-RANGE", f"curve_steps allowed=[{CURVE_STEPS_MIN},{CURVE_STEPS_MAX}]"
        )
    return value


def _prepare(
    embeddings_by_subject: Mapping[str, Sequence[Sequence[float]]],
) -> tuple[np.ndarray, np.ndarray, int]:
    """Validate + L2-normalise every vector. Returns (X, labels, n_subjects)."""
    if not isinstance(embeddings_by_subject, Mapping):
        raise EngineError("DATA-INSUFFICIENT", "embeddings must be a mapping")

    rows: list[np.ndarray] = []
    labels: list[int] = []
    dim: int | None = None
    subject_index = 0
    for _key, vectors in embeddings_by_subject.items():
        vectors = list(vectors or [])
        if not vectors:
            continue
        for vec in vectors:
            unit = l2_normalize(vec)  # raises EMB-INVALID-VECTOR
            if dim is None:
                dim = unit.shape[0]
            elif unit.shape[0] != dim:
                raise EngineError("EMB-INVALID-VECTOR", "embedding dimensions differ")
            rows.append(unit)
            labels.append(subject_index)
        subject_index += 1

    if len(rows) > MAX_EMBEDDINGS:
        raise EngineError("DATA-INSUFFICIENT", f"too many embeddings (> {MAX_EMBEDDINGS})")
    if subject_index < 2:
        raise EngineError(
            "DATA-INSUFFICIENT", "at least 2 subjects with embeddings are required"
        )
    return np.vstack(rows), np.asarray(labels, dtype=np.int64), subject_index


# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------
def pairwise_scores(
    embeddings_by_subject: Mapping[str, Sequence[Sequence[float]]],
    max_impostor_pairs: int = DEFAULT_MAX_IMPOSTOR_PAIRS,
    sample_seed: int = DEFAULT_SAMPLE_SEED,
) -> PairScores:
    """All genuine pairs, and all impostor pairs (or a seeded uniform sample).

    The old service-layer loop stopped after the first N impostor pairs,
    which only covered the first few subjects. Sampling uniformly over all
    cross-subject pairs avoids that bias, and the fixed seed keeps runs
    reproducible.
    """
    if isinstance(max_impostor_pairs, bool) or not isinstance(max_impostor_pairs, int) \
            or max_impostor_pairs < 1:
        raise EngineError("CFG-OUT-OF-RANGE", "max_impostor_pairs must be a positive int")

    X, labels, n_subjects = _prepare(embeddings_by_subject)
    n = X.shape[0]

    # Genuine: upper triangle within each subject.
    genuine_parts: list[np.ndarray] = []
    for s in range(n_subjects):
        idx = np.flatnonzero(labels == s)
        if idx.size >= 2:
            block = X[idx] @ X[idx].T
            iu = np.triu_indices(idx.size, k=1)
            genuine_parts.append(block[iu])
    genuine = np.concatenate(genuine_parts) if genuine_parts else np.empty(0)
    if genuine.size == 0:
        raise EngineError(
            "DATA-INSUFFICIENT",
            "no genuine pairs: at least one subject needs 2 or more embeddings",
        )

    counts = np.bincount(labels, minlength=n_subjects).astype(np.int64)
    impostor_total = int((n * n - int(np.sum(counts * counts))) // 2)

    if impostor_total <= max_impostor_pairs:
        parts: list[np.ndarray] = []
        for start in range(0, n, _BLOCK):
            stop = min(start + _BLOCK, n)
            sims = X[start:stop] @ X.T
            rows = np.arange(start, stop)[:, None]
            cols = np.arange(n)[None, :]
            mask = (cols > rows) & (labels[start:stop][:, None] != labels[None, :])
            parts.append(sims[mask])
        impostor = np.concatenate(parts)
        sampled, seed = False, None
    else:
        rng = np.random.default_rng(sample_seed)
        chosen: list[np.ndarray] = []
        have = 0
        while have < max_impostor_pairs:
            need = max_impostor_pairs - have
            i = rng.integers(0, n, size=need * 2)
            j = rng.integers(0, n, size=need * 2)
            keep = labels[i] != labels[j]
            i, j = i[keep][:need], j[keep][:need]
            chosen.append(np.einsum("ij,ij->i", X[i], X[j]))
            have += i.size
        impostor = np.concatenate(chosen)[:max_impostor_pairs]
        sampled, seed = True, sample_seed

    genuine = np.sort(np.clip(genuine, -1.0, 1.0))
    impostor = np.sort(np.clip(impostor, -1.0, 1.0))
    return PairScores(
        genuine=genuine,
        impostor=impostor,
        impostor_total=impostor_total,
        impostor_sampled=sampled,
        sample_seed=seed,
        subjects=n_subjects,
        embeddings=n,
        dim=int(X.shape[1]),
    )


# ---------------------------------------------------------------------------
# Error rates
# ---------------------------------------------------------------------------
def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n (robust when k = 0)."""
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6))


def _counts(genuine_sorted: np.ndarray, impostor_sorted: np.ndarray, t: float):
    false_rejects = int(np.searchsorted(genuine_sorted, t, side="left"))
    false_accepts = int(impostor_sorted.size - np.searchsorted(impostor_sorted, t, side="left"))
    return false_accepts, false_rejects


def operating_point(
    genuine_sorted: np.ndarray, impostor_sorted: np.ndarray, threshold: float
) -> OperatingPoint:
    """Exact FAR/FRR at one threshold (inputs must be sorted ascending)."""
    n_g, n_i = int(genuine_sorted.size), int(impostor_sorted.size)
    if n_g == 0 or n_i == 0:
        raise EngineError("DATA-INSUFFICIENT", "need genuine and impostor scores")
    fa, fr = _counts(genuine_sorted, impostor_sorted, threshold)
    return OperatingPoint(
        threshold=round(float(threshold), THRESHOLD_DECIMALS),
        far=round(fa / n_i, 6),
        frr=round(fr / n_g, 6),
        far_ci95=wilson_interval(fa, n_i),
        frr_ci95=wilson_interval(fr, n_g),
        false_accepts=fa,
        false_rejects=fr,
        genuine_pairs=n_g,
        impostor_pairs=n_i,
    )


def threshold_curve(
    genuine_sorted: np.ndarray, impostor_sorted: np.ndarray, steps: int = 50
) -> list[dict]:
    """FAR/FRR/TPR on an even grid that spans the observed scores (ROC/DET data)."""
    steps = validate_steps(steps)
    lo = min(float(genuine_sorted[0]), float(impostor_sorted[0]))
    hi = max(float(genuine_sorted[-1]), float(impostor_sorted[-1]))
    lo = max(-1.0, math.floor(lo * 100) / 100)
    hi = min(1.0, math.ceil(hi * 100) / 100 + 0.01)
    if hi - lo < 0.02:
        lo, hi = max(-1.0, lo - 0.01), min(1.0, hi + 0.01)

    n_g, n_i = genuine_sorted.size, impostor_sorted.size
    grid = np.linspace(lo, hi, num=steps)
    false_rejects = np.searchsorted(genuine_sorted, grid, side="left")
    false_accepts = n_i - np.searchsorted(impostor_sorted, grid, side="left")
    points = []
    for t, fr, fa in zip(grid, false_rejects, false_accepts):
        frr = fr / n_g
        points.append(
            {
                "threshold": round(float(t), THRESHOLD_DECIMALS),
                "far": round(float(fa / n_i), 6),
                "frr": round(float(frr), 6),
                "tpr": round(float(1.0 - frr), 6),
                "genuine_matches": int(n_g - fr),
                "impostor_matches": int(fa),
            }
        )
    return points


def equal_error_rate(
    genuine_sorted: np.ndarray, impostor_sorted: np.ndarray
) -> tuple[float, float]:
    """EER and its threshold, linearly interpolated at the FAR/FRR crossing."""
    candidates = np.unique(
        np.concatenate(
            [genuine_sorted, impostor_sorted,
             [np.nextafter(max(genuine_sorted[-1], impostor_sorted[-1]), np.inf)]]
        )
    )
    n_g, n_i = genuine_sorted.size, impostor_sorted.size
    frr = np.searchsorted(genuine_sorted, candidates, side="left") / n_g
    far = (n_i - np.searchsorted(impostor_sorted, candidates, side="left")) / n_i
    diff = far - frr  # starts >= 0, ends <= 0, non-increasing
    k = int(np.argmax(diff <= 0))
    if k == 0:
        eer, thr = (far[0] + frr[0]) / 2.0, candidates[0]
    else:
        d0, d1 = diff[k - 1], diff[k]
        alpha = d0 / (d0 - d1) if d0 != d1 else 0.0
        eer_far = far[k - 1] + alpha * (far[k] - far[k - 1])
        eer_frr = frr[k - 1] + alpha * (frr[k] - frr[k - 1])
        eer = (eer_far + eer_frr) / 2.0
        thr = candidates[k - 1] + alpha * (candidates[k] - candidates[k - 1])
    thr = min(1.0, max(-1.0, float(thr)))
    return round(float(eer), 6), round(thr, THRESHOLD_DECIMALS)


def lowest_threshold_for_target(impostor_sorted: np.ndarray, target_far: float) -> float:
    """Lowest threshold (4 d.p., rounded *up*) whose empirical FAR <= target.

    Rounding up can only lower FAR, so the human-readable value is never
    less secure than the exact one. Clamped to [-1, 1].
    """
    target_far = validate_target_far(target_far)
    n_i = impostor_sorted.size
    allowed = int(math.floor(target_far * n_i + 1e-9))  # max false accepts
    desc = impostor_sorted[::-1]
    raw = float(np.nextafter(desc[allowed], np.inf)) if allowed < n_i else float(desc[-1])
    factor = 10 ** THRESHOLD_DECIMALS
    thr = math.ceil(raw * factor - 1e-9) / factor
    if thr < raw:  # guard against float error in the ceil
        thr = round(thr + 1 / factor, THRESHOLD_DECIMALS)
    return round(max(-1.0, min(1.0, thr)), THRESHOLD_DECIMALS)


def recommend_threshold(
    genuine_sorted: np.ndarray, impostor_sorted: np.ndarray, target_far: float
) -> tuple[OperatingPoint, bool, tuple[float, float]]:
    """Pick the operating threshold for a target FAR.

    1. t_low = lowest threshold with FAR <= target. Any lower threshold breaks
       the security target; t_low gives the best (lowest) FRR possible.
    2. FRR stays the same for every threshold up to the next genuine score
       g_next >= t_low, while FAR can only fall. So the whole band
       [t_low, g_next] costs no extra false rejects.
    3. Recommend the middle of that band: it keeps the best FRR, lowers FAR
       below the target where the data allows, and leaves a margin on both
       sides instead of sitting exactly on an observed score.

    Returns (operating point, target_met, (band_low, band_high)).
    """
    t_low = lowest_threshold_for_target(impostor_sorted, target_far)
    factor = 10 ** THRESHOLD_DECIMALS
    idx = int(np.searchsorted(genuine_sorted, t_low, side="left"))
    if idx < genuine_sorted.size:
        t_high = math.floor(float(genuine_sorted[idx]) * factor + 1e-9) / factor
        t_high = max(t_low, min(1.0, t_high))
    else:
        t_high = t_low
    thr = round(max(t_low, min(t_high, (t_low + t_high) / 2)), THRESHOLD_DECIMALS)
    point = operating_point(genuine_sorted, impostor_sorted, thr)
    met = point.far <= validate_target_far(target_far)
    return point, met, (t_low, round(t_high, THRESHOLD_DECIMALS))


def score_summary(scores: np.ndarray) -> dict:
    q = np.percentile(scores, [5, 50, 95])
    return {
        "n": int(scores.size),
        "min": round(float(scores[0]), 4),
        "p05": round(float(q[0]), 4),
        "median": round(float(q[1]), 4),
        "p95": round(float(q[2]), 4),
        "max": round(float(scores[-1]), 4),
        "mean": round(float(np.mean(scores)), 4),
        "std": round(float(np.std(scores)), 4),
    }


def d_prime(genuine: np.ndarray, impostor: np.ndarray) -> float | None:
    """Separability of the two score distributions (higher = easier to tune)."""
    var = (float(np.var(genuine)) + float(np.var(impostor))) / 2.0
    if var <= 0.0:
        return None
    return round(abs(float(np.mean(genuine)) - float(np.mean(impostor))) / math.sqrt(var), 4)


# ---------------------------------------------------------------------------
# Orchestration -> explainable Decision
# ---------------------------------------------------------------------------
def _pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def evaluate_threshold(
    embeddings_by_subject: Mapping[str, Sequence[Sequence[float]]],
    *,
    active_threshold: float,
    target_far: float,
    config_hash: str,
    model: str,
    model_version: str,
    input_ref: str,
    curve_steps: int = 50,
    max_impostor_pairs: int = DEFAULT_MAX_IMPOSTOR_PAIRS,
    sample_seed: int = DEFAULT_SAMPLE_SEED,
) -> tuple[Decision, ThresholdReport]:
    """Run FR-3 end to end and return (Decision, ThresholdReport)."""
    timer = Timer()
    active_threshold = validate_threshold(active_threshold)
    target_far = validate_target_far(target_far)
    curve_steps = validate_steps(curve_steps)

    scores = pairwise_scores(embeddings_by_subject, max_impostor_pairs, sample_seed)
    g, i = scores.genuine, scores.impostor

    active = operating_point(g, i, active_threshold)
    recommended, target_met, band = recommend_threshold(g, i, target_far)
    eer, eer_thr = equal_error_rate(g, i)
    curve = threshold_curve(g, i, curve_steps)
    needed_impostor = int(math.ceil(ZERO_ERROR_FACTOR / target_far))

    rules: list[FiredRule] = []
    if not target_met:
        rules.append(FiredRule(
            "THR-TARGET-UNMET", "high",
            f"No threshold up to 1.0 reaches the target FAR of {_pct(target_far)}; "
            f"best achievable FAR is {_pct(recommended.far)} at {recommended.threshold}. "
            "Impostor embeddings are too similar for this model/dataset.",
        ))
    if active.far > target_far:
        rules.append(FiredRule(
            "THR-ACTIVE-FAR-EXCEEDS-TARGET", "high",
            f"The active threshold {active.threshold} accepts {active.false_accepts} of "
            f"{active.impostor_pairs} impostor pairs (FAR {_pct(active.far)}, 95% CI "
            f"{_pct(active.far_ci95[0])}-{_pct(active.far_ci95[1])}), above the target "
            f"of {_pct(target_far)}.",
        ))
    if i.size < needed_impostor or g.size < MIN_GENUINE_PAIRS:
        rules.append(FiredRule(
            "THR-LOW-CONFIDENCE", "medium",
            f"Sample too small to support the target: {i.size} impostor pairs "
            f"(need >= {needed_impostor} to claim FAR <= {_pct(target_far)} at 95% "
            f"confidence) and {g.size} genuine pairs (need >= {MIN_GENUINE_PAIRS}).",
        ))
    if target_met and recommended.frr > HIGH_FRR_WARNING:
        rules.append(FiredRule(
            "THR-RECOMMENDED-FRR-HIGH", "low",
            f"At the recommended threshold {recommended.threshold}, "
            f"{_pct(recommended.frr)} of genuine attempts are rejected "
            f"(above the {_pct(HIGH_FRR_WARNING)} usability warning level).",
        ))

    # Recommended action - concrete, not just "unsafe".
    low_conf = any(r.rule == "THR-LOW-CONFIDENCE" for r in rules)
    if not target_met:
        action = ("Do not tighten blindly: collect better-quality enrolment images or use a "
                  "stronger embedding model, then re-run the evaluation.")
    elif abs(recommended.threshold - active.threshold) < 10 ** -THRESHOLD_DECIMALS:
        action = "Keep the active threshold; it already matches the recommendation."
    else:
        action = (f"An administrator may apply threshold {recommended.threshold} "
                  f"(currently {active.threshold}).")
        if low_conf:
            action += " Enrol more consented samples first; this recommendation is low-confidence."

    reasons = [
        f"Scored {g.size} genuine and {i.size} impostor pairs from {scores.subjects} "
        f"consented subjects ({scores.embeddings} embeddings, {scores.dim}-d, model {model} "
        f"{model_version}). Rule: ACCEPT if cosine score >= threshold.",
        f"Active threshold {active.threshold}: FAR {_pct(active.far)} "
        f"({active.false_accepts}/{active.impostor_pairs}), FRR {_pct(active.frr)} "
        f"({active.false_rejects}/{active.genuine_pairs}).",
        f"Recommended threshold {recommended.threshold} for target FAR {_pct(target_far)}: "
        f"FAR {_pct(recommended.far)}, FRR {_pct(recommended.frr)}"
        + ("." if target_met else " (target NOT met).")
        + (f" Every threshold in [{band[0]}, {band[1]}] meets the target with this FRR; "
           "the recommendation is the middle of that band." if target_met and band[1] > band[0]
           else ""),
        f"Equal error rate {_pct(eer)} at threshold {eer_thr}.",
    ]
    if scores.impostor_sampled:
        reasons.append(
            f"Impostor pairs were uniformly sampled ({i.size} of {scores.impostor_total}, "
            f"seed {scores.sample_seed}) - the run is reproducible."
        )
    reasons.extend(r.reason for r in rules)
    reasons.append(f"Recommended action: {action}")

    severity = "info"
    for r in rules:
        if _SEVERITY_ORDER.index(r.severity) > _SEVERITY_ORDER.index(severity):
            severity = r.severity

    confidence = min(1.0, i.size / needed_impostor) * min(1.0, g.size / MIN_GENUINE_PAIRS)

    report = ThresholdReport(
        target_far=target_far,
        active=active,
        recommended=recommended,
        target_met=target_met,
        target_band=band,
        eer=eer,
        eer_threshold=eer_thr,
        curve=curve,
        genuine_summary=score_summary(g),
        impostor_summary=score_summary(i),
        d_prime=d_prime(g, i),
        min_impostor_pairs_for_target=needed_impostor,
        min_genuine_pairs=MIN_GENUINE_PAIRS,
        subjects=scores.subjects,
        embeddings=scores.embeddings,
        dim=scores.dim,
        genuine_pairs=int(g.size),
        impostor_pairs=int(i.size),
        impostor_pairs_total=scores.impostor_total,
        impostor_sampled=scores.impostor_sampled,
        sample_seed=scores.sample_seed,
        rules=rules,
        recommended_action=action,
    )

    decision = Decision.create(
        stage="threshold",
        status="flagged" if rules else "completed",
        outcome="THRESHOLD_EVALUATION_COMPLETED",
        score=recommended.far,
        threshold=recommended.threshold,
        severity=severity,
        confidence=round(confidence, 4),
        rules_fired=[r.rule for r in rules],
        reasons=reasons,
        config_hash=config_hash,
        input_ref=input_ref,
        latency_ms=timer.ms(),
        model=model,
        model_version=model_version,
    )
    return decision, report