"""FR-3 engine tests (pure numpy - no server, no database).

Maps to evaluation cases:
  T1  false accept / false reject rates      -> test_t1_*
  T2  threshold curves                       -> test_t2_*
  misuse / edge cases                        -> test_edge_*
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from engine.errors import EngineError
from engine.threshold import (
    MIN_GENUINE_PAIRS,
    equal_error_rate,
    evaluate_threshold,
    operating_point,
    pairwise_scores,
    recommend_threshold,
    threshold_curve,
    wilson_interval,
)

CFG_HASH = "0" * 64


def synthetic_dataset(subjects=12, per_subject=4, dim=64, noise=0.35, seed=7):
    """Each subject = random identity vector + small per-sample noise."""
    rng = np.random.default_rng(seed)
    data = {}
    for s in range(subjects):
        base = rng.normal(size=dim)
        data[f"S{s:03d}"] = [(base + rng.normal(scale=noise, size=dim)).tolist()
                             for _ in range(per_subject)]
    return data


def run(data, **kw):
    params = dict(
        active_threshold=0.5, target_far=0.01, config_hash=CFG_HASH,
        model="synthetic-64d", model_version="test", input_ref="eval:threshold:test",
    )
    params.update(kw)
    return evaluate_threshold(data, **params)


# ---------------------------------------------------------------- pairing
def test_pair_counts_are_exact():
    data = synthetic_dataset(subjects=5, per_subject=3)
    s = pairwise_scores(data)
    assert s.genuine.size == 5 * 3          # C(3,2) per subject
    assert s.impostor.size == 3 * 3 * 10    # 9 cross pairs * C(5,2) subject pairs
    assert s.impostor_total == s.impostor.size
    assert not s.impostor_sampled
    assert np.all(np.diff(s.genuine) >= 0) and np.all(np.diff(s.impostor) >= 0)
    assert s.genuine.min() >= -1 and s.impostor.max() <= 1


def test_impostor_sampling_is_reproducible_and_capped():
    data = synthetic_dataset(subjects=20, per_subject=5)
    a = pairwise_scores(data, max_impostor_pairs=500, sample_seed=1)
    b = pairwise_scores(data, max_impostor_pairs=500, sample_seed=1)
    assert a.impostor_sampled and a.impostor.size == 500
    assert a.impostor_total == (100 * 100 - 20 * 25) // 2
    np.testing.assert_array_equal(a.impostor, b.impostor)


# ---------------------------------------------------------------- T1
def test_t1_far_frr_hand_computed():
    g = np.sort(np.array([0.9, 0.8, 0.7, 0.4]))
    i = np.sort(np.array([0.1, 0.2, 0.55, 0.6, 0.3]))
    p = operating_point(g, i, 0.5)
    assert p.false_rejects == 1 and p.frr == 0.25      # 0.4 < 0.5
    assert p.false_accepts == 2 and p.far == 0.4       # 0.55, 0.6 >= 0.5
    # score exactly at threshold is ACCEPTED
    assert operating_point(g, i, 0.6).false_accepts == 1


@pytest.mark.parametrize("noise", [0.3, 0.9, 1.4])
def test_t1_recommended_threshold_meets_target_with_best_frr(noise):
    data = synthetic_dataset(subjects=30, per_subject=4, noise=noise)
    s = pairwise_scores(data)
    point, met, (t_low, t_high) = recommend_threshold(s.genuine, s.impostor, 0.01)
    assert met and point.far <= 0.01
    assert t_low <= point.threshold <= t_high
    # t_low is the lowest compliant threshold: one step lower breaks the target
    assert operating_point(s.genuine, s.impostor, t_low).far <= 0.01
    assert operating_point(s.genuine, s.impostor, round(t_low - 0.0001, 4)).far > 0.01
    # the recommendation costs no extra false rejects compared with t_low
    assert point.frr == operating_point(s.genuine, s.impostor, t_low).frr


def test_t1_separable_data_does_not_loosen_security():
    """With a wide gap between genuine and impostor scores, the pick sits inside
    the gap - not at the loosest threshold that merely touches the target."""
    g = np.sort(np.linspace(0.6, 0.9, 50))
    i = np.sort(np.linspace(-0.3, 0.2, 400))
    point, met, (t_low, t_high) = recommend_threshold(g, i, 0.05)
    assert met and t_low < 0.2 and t_high == 0.6
    assert point.far == 0.0 and point.frr == 0.0
    assert 0.2 < point.threshold < 0.6


def test_t1_evaluation_flags_insecure_active_threshold():
    data = synthetic_dataset(subjects=30, per_subject=4, noise=0.9)
    decision, report = run(data, active_threshold=-0.5)  # accepts almost everyone
    assert report.active.far > 0.01
    assert "THR-ACTIVE-FAR-EXCEEDS-TARGET" in decision.rules_fired
    assert decision.status == "flagged" and decision.severity == "high"
    assert any("Recommended action" in r for r in decision.reasons)


def test_t1_good_dataset_completes_without_warnings():
    data = synthetic_dataset(subjects=40, per_subject=6, noise=0.2)
    decision, report = run(data, active_threshold=0.6, target_far=0.01)
    assert report.genuine_pairs >= MIN_GENUINE_PAIRS
    assert report.impostor_pairs >= report.min_impostor_pairs_for_target
    assert report.target_met
    assert decision.status == "completed", decision.reasons
    assert decision.rules_fired == ()
    assert decision.confidence == 1.0
    assert decision.stage == "threshold" and decision.threshold == report.recommended.threshold


# ---------------------------------------------------------------- T2
def test_t2_curve_is_monotonic_and_has_requested_steps():
    data = synthetic_dataset()
    s = pairwise_scores(data)
    curve = threshold_curve(s.genuine, s.impostor, steps=40)
    assert len(curve) == 40
    fars = [p["far"] for p in curve]
    frrs = [p["frr"] for p in curve]
    assert all(a >= b for a, b in zip(fars, fars[1:]))   # FAR falls as threshold rises
    assert all(a <= b for a, b in zip(frrs, frrs[1:]))   # FRR rises
    assert fars[0] == 1.0 and frrs[0] == 0.0             # grid starts below all scores
    for p in curve:
        assert math.isclose(p["tpr"], 1 - p["frr"], abs_tol=1e-6)


def test_t2_eer_is_where_far_meets_frr():
    data = synthetic_dataset(noise=0.8)
    s = pairwise_scores(data)
    eer, thr = equal_error_rate(s.genuine, s.impostor)
    p = operating_point(s.genuine, s.impostor, thr)
    assert 0.0 <= eer <= 0.5
    assert abs(p.far - p.frr) < 0.15        # near the crossing on a small set
    assert min(p.far, p.frr) - 0.02 <= eer <= max(p.far, p.frr) + 0.02


def test_t2_perfect_separation_has_zero_eer():
    g = np.sort(np.array([0.9, 0.95, 0.85]))
    i = np.sort(np.array([0.1, 0.0, 0.2]))
    eer, thr = equal_error_rate(g, i)
    assert eer == 0.0 and 0.2 < thr <= 0.85


# ---------------------------------------------------------------- confidence / rules
def test_small_sample_is_flagged_low_confidence():
    data = synthetic_dataset(subjects=3, per_subject=2)
    decision, report = run(data)
    assert "THR-LOW-CONFIDENCE" in decision.rules_fired
    assert decision.confidence < 1.0
    assert "low-confidence" in report.recommended_action or not report.target_met


def test_identical_impostors_mean_target_unmet():
    v = [1.0] + [0.0] * 7
    data = {"A": [v, v], "B": [v, v]}   # everyone has the same embedding
    decision, report = run(data)
    assert not report.target_met
    assert "THR-TARGET-UNMET" in decision.rules_fired
    assert report.recommended.threshold == 1.0


def test_wilson_interval_handles_zero_errors():
    lo, hi = wilson_interval(0, 300)
    assert lo == 0.0 and 0.0 < hi < 0.02


def test_report_contains_no_identifiers_or_vectors():
    data = synthetic_dataset(subjects=4, per_subject=3)
    _, report = run(data)
    text = str(report.to_dict())
    assert "S000" not in text and "S003" not in text


# ---------------------------------------------------------------- edge / misuse
@pytest.mark.parametrize("bad", [0.0, 0.9, float("nan"), float("inf"), True, "0.01"])
def test_edge_bad_target_far_rejected(bad):
    with pytest.raises(EngineError) as e:
        run(synthetic_dataset(), target_far=bad)
    assert e.value.code in ("CFG-OUT-OF-RANGE", "CFG-INVALID-TYPE")


@pytest.mark.parametrize("bad", [1.5, -2, float("nan"), None])
def test_edge_bad_active_threshold_rejected(bad):
    with pytest.raises(EngineError):
        run(synthetic_dataset(), active_threshold=bad)


@pytest.mark.parametrize("steps", [0, 9, 501, 2.5])
def test_edge_bad_steps_rejected(steps):
    with pytest.raises(EngineError):
        run(synthetic_dataset(), curve_steps=steps)


def test_edge_single_subject_rejected():
    with pytest.raises(EngineError) as e:
        run({"A": [[1, 0, 0], [0.9, 0.1, 0]]})
    assert e.value.code == "DATA-INSUFFICIENT"


def test_edge_no_genuine_pairs_rejected():
    with pytest.raises(EngineError) as e:
        run({"A": [[1, 0, 0]], "B": [[0, 1, 0]]})
    assert e.value.code == "DATA-INSUFFICIENT"


@pytest.mark.parametrize("vec", [[float("nan"), 1, 0], [0, 0, 0], ["x", 1, 2]])
def test_edge_invalid_vectors_rejected(vec):
    with pytest.raises(EngineError) as e:
        run({"A": [[1, 0, 0], vec], "B": [[0, 1, 0]]})
    assert e.value.code == "EMB-INVALID-VECTOR"


def test_edge_mixed_dimensions_rejected():
    with pytest.raises(EngineError) as e:
        run({"A": [[1, 0, 0], [1, 0.1, 0]], "B": [[0, 1, 0, 0]]})
    assert e.value.code == "EMB-INVALID-VECTOR"


def test_deterministic_results_for_same_input():
    data = synthetic_dataset()
    d1, r1 = run(data)
    d2, r2 = run(data)
    assert r1.to_dict() == r2.to_dict()
    assert d1.reasons == d2.reasons and d1.decision_id != d2.decision_id