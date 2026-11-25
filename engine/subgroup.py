"""FR-4: Subgroup metrics / demographic bias audit (security engine, Layer 3).

Pure numpy - no web framework, no database.

For every self-reported demographic group the engine measures, at ONE
operating threshold (normally the active policy threshold from FR-3):

* FRR  - genuine pairs of the group's subjects that are rejected
* FAR  - impostor pairs where BOTH subjects are in the group
         (same-demographic impostors: the hardest and most relevant case,
         as used in NIST FRVT demographic reports)
* cross-group FAR - impostor pairs between the group and everyone else
* 95% Wilson intervals for each rate, score distribution summaries,
  d-prime, and the threshold this group alone would need for the target FAR.

Disparity is only called when it is BOTH larger than a tolerance AND
statistically supported (the worst group's 95% interval lies entirely above
the best group's). A large gap on tiny samples is reported as
"unconfirmed" with a named rule, never silently as bias or as no bias.

Privacy: groups with fewer than MIN_REPORTABLE_SUBJECTS subjects are
suppressed (counts only, no rates), because a rate for one or two people is
effectively that person's biometric result. The "undisclosed" group is
reported but never used for disparity comparisons. No subject identifiers
or vectors appear in the report.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Mapping, Sequence

import numpy as np

from .consent import GROUP_RE
from .decision import Decision, Timer
from .embeddings import l2_normalize
from .errors import EngineError
from .threshold import (
    d_prime,
    lowest_threshold_for_target,
    score_summary,
    validate_target_far,
    validate_threshold,
    wilson_interval,
)

SUBGROUP_ENGINE_VERSION = "fr4-subgroup-1.0.0"

UNDISCLOSED = "undisclosed"
MIN_REPORTABLE_SUBJECTS = 3          # small-cell suppression (privacy)
FRR_GAP_TOLERANCE = 0.05             # 5 percentage points between groups
# FAR gap tolerance = the policy's target FAR (a gap bigger than the whole
# error budget is material).
MAX_WITHIN_IMPOSTOR_PAIRS = 200_000  # per group; above this -> seeded sample
MAX_CROSS_PAIRS = 2_000_000          # per group; above this -> seeded sample
MAX_EMBEDDINGS = 20_000
MAX_GROUPS = 50
MIN_GROUP_N_RANGE = (5, 1000)        # same range as policy.TUNABLES
DEFAULT_SAMPLE_SEED = 20_26
_BLOCK = 512

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FiredRule:
    rule: str
    severity: str
    reason: str


@dataclass
class GroupMetrics:
    group: str
    subjects: int
    embeddings: int
    status: str                      # ok | low_sample | suppressed | no_pairs
    eligible: bool                   # used for disparity comparisons
    genuine_pairs: int = 0
    impostor_pairs: int = 0
    cross_pairs: int = 0
    impostor_sampled: bool = False
    cross_sampled: bool = False
    frr: float | None = None
    frr_ci95: list[float] | None = None
    false_rejects: int | None = None
    far: float | None = None
    far_ci95: list[float] | None = None
    false_accepts: int | None = None
    far_cross: float | None = None
    far_cross_ci95: list[float] | None = None
    group_threshold_for_target: float | None = None
    d_prime: float | None = None
    genuine_summary: dict = field(default_factory=dict)
    impostor_summary: dict = field(default_factory=dict)
    warning: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Comparison:
    metric: str                      # "frr" | "far"
    best_group: str | None
    worst_group: str | None
    best: float | None
    worst: float | None
    gap: float
    ratio: float | None
    tolerance: float
    significant: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SubgroupReport:
    threshold: float
    threshold_source: str
    target_far: float
    min_group_n: int
    groups: list[GroupMetrics]
    frr_comparison: Comparison
    far_comparison: Comparison
    eligible_groups: list[str]
    suppressed_groups: int
    rules: list[FiredRule]
    recommended_action: str
    sample_seed: int | None
    engine_version: str = SUBGROUP_ENGINE_VERSION

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "threshold_source": self.threshold_source,
            "target_far": self.target_far,
            "min_group_n": self.min_group_n,
            "min_reportable_subjects": MIN_REPORTABLE_SUBJECTS,
            "frr_gap_tolerance": FRR_GAP_TOLERANCE,
            "far_gap_tolerance": self.target_far,
            "groups": [g.to_dict() for g in self.groups],
            "frr_comparison": self.frr_comparison.to_dict(),
            "far_comparison": self.far_comparison.to_dict(),
            "eligible_groups": list(self.eligible_groups),
            "suppressed_groups": self.suppressed_groups,
            "rules": [asdict(r) for r in self.rules],
            "recommended_action": self.recommended_action,
            "sample_seed": self.sample_seed,
            "engine_version": self.engine_version,
        }


# ---------------------------------------------------------------------------
# Validation / preparation
# ---------------------------------------------------------------------------
def validate_min_group_n(value) -> int:
    lo, hi = MIN_GROUP_N_RANGE
    if isinstance(value, bool) or not isinstance(value, int):
        raise EngineError("CFG-INVALID-TYPE", "min_group_n must be an integer")
    if not lo <= value <= hi:
        raise EngineError("CFG-OUT-OF-RANGE", f"min_group_n allowed=[{lo},{hi}]")
    return value


def normalize_group(label) -> str:
    if label is None:
        return UNDISCLOSED
    if not isinstance(label, str):
        raise EngineError("CON-INVALID", "group label must be text")
    label = label.strip().lower()
    if not label:
        return UNDISCLOSED
    if not GROUP_RE.match(label):   # same rule as consent intake (FR-1)
        raise EngineError("CON-INVALID", "group label format")
    return label


def _prepare(embeddings_by_subject, group_of):
    """Returns X (N,d), subject label per row, group index per row, group names."""
    if not isinstance(embeddings_by_subject, Mapping) or not isinstance(group_of, Mapping):
        raise EngineError("DATA-INSUFFICIENT", "embeddings and groups must be mappings")

    rows, subj, grp = [], [], []
    group_names: list[str] = []
    group_index: dict[str, int] = {}
    dim = None
    s_idx = 0
    for key, vectors in embeddings_by_subject.items():
        vectors = list(vectors or [])
        if not vectors:
            continue
        g = normalize_group(group_of.get(key))
        if g not in group_index:
            group_index[g] = len(group_names)
            group_names.append(g)
        for vec in vectors:
            unit = l2_normalize(vec)
            if dim is None:
                dim = unit.shape[0]
            elif unit.shape[0] != dim:
                raise EngineError("EMB-INVALID-VECTOR", "embedding dimensions differ")
            rows.append(unit)
            subj.append(s_idx)
            grp.append(group_index[g])
        s_idx += 1

    if not rows:
        raise EngineError("DATA-INSUFFICIENT", "no embeddings to audit")
    if len(rows) > MAX_EMBEDDINGS:
        raise EngineError("DATA-INSUFFICIENT", f"too many embeddings (> {MAX_EMBEDDINGS})")
    if len(group_names) > MAX_GROUPS:
        raise EngineError("DATA-INSUFFICIENT", f"too many groups (> {MAX_GROUPS})")
    return (np.vstack(rows), np.asarray(subj, dtype=np.int64),
            np.asarray(grp, dtype=np.int64), group_names)


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------
def _genuine_scores(X: np.ndarray, subj: np.ndarray) -> np.ndarray:
    parts = []
    for s in np.unique(subj):
        idx = np.flatnonzero(subj == s)
        if idx.size >= 2:
            block = X[idx] @ X[idx].T
            parts.append(block[np.triu_indices(idx.size, k=1)])
    return np.sort(np.concatenate(parts)) if parts else np.empty(0)


def _within_impostor_scores(X, subj, cap, rng) -> tuple[np.ndarray, bool]:
    """Impostor pairs between different subjects inside one group."""
    n = X.shape[0]
    counts = np.unique(subj, return_counts=True)[1].astype(np.int64)
    total = int((n * n - int(np.sum(counts * counts))) // 2)
    if total == 0:
        return np.empty(0), False
    if total <= cap:
        parts = []
        for start in range(0, n, _BLOCK):
            stop = min(start + _BLOCK, n)
            sims = X[start:stop] @ X.T
            rows = np.arange(start, stop)[:, None]
            mask = (np.arange(n)[None, :] > rows) & (subj[start:stop][:, None] != subj[None, :])
            parts.append(sims[mask])
        return np.sort(np.clip(np.concatenate(parts), -1, 1)), False
    out, have = [], 0
    while have < cap:
        need = cap - have
        i, j = rng.integers(0, n, need * 2), rng.integers(0, n, need * 2)
        keep = subj[i] != subj[j]
        i, j = i[keep][:need], j[keep][:need]
        out.append(np.einsum("ij,ij->i", X[i], X[j]))
        have += i.size
    return np.sort(np.clip(np.concatenate(out)[:cap], -1, 1)), True


def _cross_counts(Xg, Xo, threshold, cap, rng) -> tuple[int, int, bool]:
    """(accepted, total, sampled) for group-vs-others impostor pairs."""
    m, k = Xg.shape[0], Xo.shape[0]
    total = m * k
    if total == 0:
        return 0, 0, False
    if total <= cap:
        accepted = 0
        for start in range(0, m, _BLOCK):
            accepted += int(np.count_nonzero(Xg[start:start + _BLOCK] @ Xo.T >= threshold))
        return accepted, total, False
    i, j = rng.integers(0, m, cap), rng.integers(0, k, cap)
    sims = np.einsum("ij,ij->i", Xg[i], Xo[j])
    return int(np.count_nonzero(sims >= threshold)), cap, True


def _rate(k: int, n: int) -> tuple[float, list[float]]:
    lo, hi = wilson_interval(k, n)
    return round(k / n, 6), [lo, hi]


def _compare(groups: list[GroupMetrics], metric: str, tolerance: float) -> Comparison:
    rated = [g for g in groups if g.eligible and getattr(g, metric) is not None]
    if len(rated) < 2:
        return Comparison(metric, None, None, None, None, 0.0, None, tolerance, False)
    best = min(rated, key=lambda g: (getattr(g, metric), g.group))
    worst = max(rated, key=lambda g: (getattr(g, metric), g.group))
    b, w = getattr(best, metric), getattr(worst, metric)
    gap = round(w - b, 6)
    ratio = round(w / b, 3) if b > 0 else None
    ci_best, ci_worst = getattr(best, f"{metric}_ci95"), getattr(worst, f"{metric}_ci95")
    significant = bool(ci_worst[0] > ci_best[1])
    return Comparison(metric, best.group, worst.group, b, w, gap, ratio, tolerance, significant)


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.2f}%"


# ---------------------------------------------------------------------------
# Orchestration -> explainable Decision
# ---------------------------------------------------------------------------
def audit_subgroups(
    embeddings_by_subject: Mapping[str, Sequence[Sequence[float]]],
    group_of: Mapping[str, str],
    *,
    threshold: float,
    target_far: float,
    min_group_n: int,
    config_hash: str,
    model: str,
    model_version: str,
    input_ref: str,
    threshold_source: str = "policy",
    sample_seed: int = DEFAULT_SAMPLE_SEED,
) -> tuple[Decision, SubgroupReport]:
    timer = Timer()
    threshold = validate_threshold(threshold)
    target_far = validate_target_far(target_far)
    min_group_n = validate_min_group_n(min_group_n)
    if threshold_source not in ("policy", "override"):
        raise EngineError("CFG-INVALID-TYPE", "threshold_source")

    X, subj, grp, names = _prepare(embeddings_by_subject, group_of)
    rng = np.random.default_rng(sample_seed)
    any_sampled = False

    groups: list[GroupMetrics] = []
    for gi, name in enumerate(names):
        in_g = grp == gi
        Xg, subj_g = X[in_g], subj[in_g]
        n_subjects = int(np.unique(subj_g).size)
        gm = GroupMetrics(group=name, subjects=n_subjects, embeddings=int(Xg.shape[0]),
                          status="ok", eligible=False)

        if n_subjects < MIN_REPORTABLE_SUBJECTS:
            gm.status = "suppressed"
            gm.warning = (f"Fewer than {MIN_REPORTABLE_SUBJECTS} subjects: rates are "
                          "suppressed to protect individuals.")
            groups.append(gm)
            continue

        genuine = _genuine_scores(Xg, subj_g)
        impostor, sampled = _within_impostor_scores(Xg, subj_g, MAX_WITHIN_IMPOSTOR_PAIRS, rng)
        acc_x, tot_x, sampled_x = _cross_counts(Xg, X[~in_g], threshold, MAX_CROSS_PAIRS, rng)
        any_sampled = any_sampled or sampled or sampled_x

        gm.genuine_pairs, gm.impostor_pairs, gm.cross_pairs = int(genuine.size), int(impostor.size), tot_x
        gm.impostor_sampled, gm.cross_sampled = sampled, sampled_x

        if genuine.size:
            fr = int(np.searchsorted(genuine, threshold, side="left"))
            gm.false_rejects = fr
            gm.frr, gm.frr_ci95 = _rate(fr, genuine.size)
            gm.genuine_summary = score_summary(genuine)
        if impostor.size:
            fa = int(impostor.size - np.searchsorted(impostor, threshold, side="left"))
            gm.false_accepts = fa
            gm.far, gm.far_ci95 = _rate(fa, impostor.size)
            gm.impostor_summary = score_summary(impostor)
            gm.group_threshold_for_target = lowest_threshold_for_target(impostor, target_far)
        if tot_x:
            gm.far_cross, gm.far_cross_ci95 = _rate(acc_x, tot_x)
        if genuine.size and impostor.size:
            gm.d_prime = d_prime(genuine, impostor)

        if not genuine.size or not impostor.size:
            gm.status = "no_pairs"
            gm.warning = ("Needs subjects with 2+ samples (genuine pairs) and 2+ subjects "
                          "(impostor pairs) to compute both rates.")
        elif n_subjects < min_group_n:
            gm.status = "low_sample"
            gm.warning = (f"Sample size N={n_subjects} < {min_group_n} provides low statistical "
                          "confidence (wide 95% confidence interval).")
        gm.eligible = name != UNDISCLOSED and gm.status in ("ok", "low_sample")
        groups.append(gm)

    groups.sort(key=lambda g: g.group)
    frr_cmp = _compare(groups, "frr", FRR_GAP_TOLERANCE)
    far_cmp = _compare(groups, "far", target_far)
    eligible = [g.group for g in groups if g.eligible]
    suppressed = sum(1 for g in groups if g.status == "suppressed")

    # ---- rules -------------------------------------------------------------
    rules: list[FiredRule] = []
    actions: list[str] = []
    if len(eligible) < 2:
        rules.append(FiredRule(
            "BIAS-INSUFFICIENT-GROUPS", "medium",
            f"Only {len(eligible)} group(s) can be compared (undisclosed, suppressed and "
            "groups without both pair types are excluded); disparity cannot be assessed.",
        ))
        actions.append("Enrol more consented subjects with a disclosed group label.")

    for cmp_, label, rule_base in ((frr_cmp, "FRR (false rejects)", "FRR"),
                                   (far_cmp, "FAR (false accepts)", "FAR")):
        if cmp_.worst_group is None or cmp_.gap <= cmp_.tolerance:
            continue
        text = (f"{label} for '{cmp_.worst_group}' is {_pct(cmp_.worst)} vs "
                f"{_pct(cmp_.best)} for '{cmp_.best_group}' (gap {_pct(cmp_.gap)}, "
                f"tolerance {_pct(cmp_.tolerance)}"
                + (f", ratio {cmp_.ratio}x)" if cmp_.ratio else ")"))
        if cmp_.significant:
            rules.append(FiredRule(f"BIAS-{rule_base}-DISPARITY", "high",
                                   text + "; the 95% intervals do not overlap."))
            actions.append(
                f"Investigate {rule_base} disparity for '{cmp_.worst_group}': check image "
                "quality/lighting for that group and consider a fairer model before deployment."
            )
        else:
            rules.append(FiredRule(f"BIAS-{rule_base}-GAP-UNCONFIRMED", "low",
                                   text + "; the 95% intervals overlap, so the gap is not "
                                   "statistically confirmed."))
            actions.append(f"Collect more samples for '{cmp_.worst_group}' and "
                           f"'{cmp_.best_group}' to confirm or rule out the {rule_base} gap.")

    over_target = [g for g in groups if g.eligible and g.far_ci95 and g.far_ci95[0] > target_far]
    if over_target:
        names_ = ", ".join(f"'{g.group}' ({_pct(g.far)}, would need threshold "
                           f"{g.group_threshold_for_target})" for g in over_target)
        rules.append(FiredRule(
            "BIAS-GROUP-FAR-EXCEEDS-TARGET", "high",
            f"Same-group impostors are accepted above the target FAR of {_pct(target_far)} "
            f"even at the lower 95% bound: {names_}.",
        ))
        actions.append("Do not rely on the global threshold for these groups; re-run FR-3 "
                       "and review whether a stricter threshold is acceptable.")

    low = [g.group for g in groups if g.eligible and g.status == "low_sample"]
    if low:
        rules.append(FiredRule(
            "BIAS-LOW-SAMPLE", "medium",
            f"{len(low)} group(s) have fewer than {min_group_n} subjects: "
            f"{', '.join(low[:10])}. Their rates have wide confidence intervals.",
        ))
        if not any("Collect more" in a or "Enrol more" in a for a in actions):
            actions.append(f"Enrol at least {min_group_n} consented subjects per group.")

    if not actions:
        actions.append("No action required: error rates are within tolerance across groups.")
    action = " ".join(dict.fromkeys(actions))  # de-duplicate, keep order

    # ---- decision ------------------------------------------------------------
    reasons = [
        f"Audited {len(groups)} group(s) at threshold {threshold} ({threshold_source}); "
        f"model {model} {model_version}. FAR uses same-group impostor pairs.",
        f"FRR: best '{frr_cmp.best_group}' {_pct(frr_cmp.best)}, worst "
        f"'{frr_cmp.worst_group}' {_pct(frr_cmp.worst)}, gap {_pct(frr_cmp.gap)}.",
        f"FAR: best '{far_cmp.best_group}' {_pct(far_cmp.best)}, worst "
        f"'{far_cmp.worst_group}' {_pct(far_cmp.worst)}, gap {_pct(far_cmp.gap)}.",
    ]
    if suppressed:
        reasons.append(f"{suppressed} group(s) suppressed (< {MIN_REPORTABLE_SUBJECTS} subjects).")
    if any(g.group == UNDISCLOSED for g in groups):
        reasons.append("The 'undisclosed' group is reported but excluded from comparisons.")
    if any_sampled:
        reasons.append(f"Some pair sets were uniformly sampled (seed {sample_seed}); reproducible.")
    reasons.extend(r.reason for r in rules)
    reasons.append(f"Recommended action: {action}")

    severity = "info"
    for r in rules:
        if _SEVERITY_ORDER.index(r.severity) > _SEVERITY_ORDER.index(severity):
            severity = r.severity

    elig = [g for g in groups if g.eligible]
    confidence = (min(min(1.0, g.subjects / min_group_n) for g in elig) if len(elig) >= 2 else 0.0)

    report = SubgroupReport(
        threshold=round(threshold, 4),
        threshold_source=threshold_source,
        target_far=target_far,
        min_group_n=min_group_n,
        groups=groups,
        frr_comparison=frr_cmp,
        far_comparison=far_cmp,
        eligible_groups=eligible,
        suppressed_groups=suppressed,
        rules=rules,
        recommended_action=action,
        sample_seed=sample_seed if any_sampled else None,
    )
    decision = Decision.create(
        stage="subgroup",
        status="flagged" if rules else "completed",
        outcome="SUBGROUP_BIAS_AUDIT_COMPLETED",
        score=frr_cmp.gap,
        threshold=round(threshold, 4),
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