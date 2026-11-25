"""FR-4 engine tests (pure numpy - no server, no database).

Maps to evaluation case T5 (bias reporting) plus edge/misuse cases.
"""

from __future__ import annotations

import numpy as np
import pytest

from engine.errors import EngineError
from engine.subgroup import (
    MIN_REPORTABLE_SUBJECTS,
    UNDISCLOSED,
    audit_subgroups,
    normalize_group,
)

CFG = "0" * 64


def make_group(rng, name, subjects, per_subject=4, dim=64, noise=0.35, shared=0.0, start=0):
    """Return (embeddings, groups) for one synthetic group.

    noise  -> larger = genuine pairs less similar (raises FRR)
    shared -> common component added to every identity (raises same-group FAR)
    """
    common = rng.normal(size=dim)
    emb, grp = {}, {}
    for s in range(subjects):
        key = f"{name}-{start + s}"
        base = rng.normal(size=dim) + shared * common
        emb[key] = [(base + rng.normal(scale=noise, size=dim)).tolist() for _ in range(per_subject)]
        grp[key] = name
    return emb, grp


def dataset(*specs, seed=3):
    rng = np.random.default_rng(seed)
    emb, grp = {}, {}
    for spec in specs:
        e, g = make_group(rng, **spec)
        emb.update(e)
        grp.update(g)
    return emb, grp


def run(emb, grp, **kw):
    params = dict(threshold=0.5, target_far=0.01, min_group_n=30, config_hash=CFG,
                  model="synthetic-64d", model_version="t", input_ref="eval:bias:test")
    params.update(kw)
    return audit_subgroups(emb, grp, **params)


def by_name(report):
    return {g.group: g for g in report.groups}


# ---------------------------------------------------------------- T5 core
def test_t5_balanced_groups_complete_without_disparity():
    emb, grp = dataset(dict(name="a", subjects=35), dict(name="b", subjects=35, start=100))
    d, r = run(emb, grp)
    assert d.status == "completed", d.reasons
    assert d.rules_fired == ()
    assert set(r.eligible_groups) == {"a", "b"}
    assert d.stage == "subgroup" and d.confidence == 1.0


def test_t5_frr_disparity_is_detected_and_named():
    emb, grp = dataset(dict(name="clear", subjects=35, noise=0.3),
                       dict(name="noisy", subjects=35, noise=1.4, start=100))
    d, r = run(emb, grp)
    g = by_name(r)
    assert g["noisy"].frr > g["clear"].frr
    assert "BIAS-FRR-DISPARITY" in d.rules_fired
    assert d.severity == "high" and d.status == "flagged"
    assert r.frr_comparison.worst_group == "noisy" and r.frr_comparison.significant
    assert any("noisy" in reason for reason in d.reasons)


def test_t5_same_group_far_disparity_is_detected():
    emb, grp = dataset(dict(name="distinct", subjects=35),
                       dict(name="similar", subjects=35, shared=2.5, start=100))
    d, r = run(emb, grp)
    g = by_name(r)
    assert g["similar"].far > g["distinct"].far
    assert "BIAS-GROUP-FAR-EXCEEDS-TARGET" in d.rules_fired
    assert "BIAS-FAR-DISPARITY" in d.rules_fired
    # explains what threshold that group would need
    assert g["similar"].group_threshold_for_target > 0.5


def test_t5_small_gap_on_small_groups_is_unconfirmed_not_bias():
    emb, grp = dataset(dict(name="a", subjects=5, per_subject=2, noise=0.3),
                       dict(name="b", subjects=5, per_subject=2, noise=0.9, start=100))
    d, r = run(emb, grp)
    assert r.frr_comparison.gap > 0.05            # visible gap (0% vs 40%) ...
    assert not r.frr_comparison.significant       # ... but only 5 pairs per group
    assert "BIAS-FRR-DISPARITY" not in d.rules_fired
    assert "BIAS-FRR-GAP-UNCONFIRMED" in d.rules_fired
    assert "BIAS-LOW-SAMPLE" in d.rules_fired
    assert d.confidence < 1.0


def test_rates_match_hand_count():
    # group "x": two subjects, orthogonal identities -> impostor score 0
    e = {"x1": [[1, 0, 0, 0], [0.9, 0.1, 0, 0]], "x2": [[0, 1, 0, 0], [0, 0.95, 0.05, 0]],
         "x3": [[0, 0, 1, 0], [0, 0, 0.2, 0.9]]}          # x3 genuine pair is a reject
    g = {k: "x" for k in e}
    e |= {"y1": [[0, 0, 0, 1], [0, 0, 0.1, 1]], "y2": [[1, 1, 0, 0], [1, 1, 0.1, 0]],
          "y3": [[1, 0, 1, 0], [1, 0, 1, 0.1]]}
    g |= {k: "y" for k in e if k.startswith("y")}
    _, r = run(e, g, min_group_n=5)
    x = by_name(r)["x"]
    assert x.genuine_pairs == 3 and x.false_rejects == 1 and x.frr == pytest.approx(1 / 3, abs=1e-6)
    assert x.impostor_pairs == 12      # 3 subjects * 2 samples -> (36 - 12) / 2


# ---------------------------------------------------------------- privacy
def test_small_groups_are_suppressed():
    emb, grp = dataset(dict(name="big1", subjects=10), dict(name="big2", subjects=10, start=50),
                       dict(name="tiny", subjects=MIN_REPORTABLE_SUBJECTS - 1, start=100))
    d, r = run(emb, grp)
    t = by_name(r)["tiny"]
    assert t.status == "suppressed" and not t.eligible
    assert t.frr is None and t.far is None and t.genuine_summary == {}
    assert r.suppressed_groups == 1


def test_undisclosed_is_reported_but_not_compared():
    emb, grp = dataset(dict(name="a", subjects=8), dict(name="b", subjects=8, start=50),
                       dict(name="x", subjects=8, noise=1.5, start=100))
    for k in list(grp):
        if grp[k] == "x":
            grp[k] = ""                      # blank -> undisclosed
    _, r = run(emb, grp)
    u = by_name(r)[UNDISCLOSED]
    assert u.frr is not None and not u.eligible
    assert UNDISCLOSED not in r.eligible_groups
    assert r.frr_comparison.worst_group != UNDISCLOSED


def test_report_has_no_subject_identifiers():
    emb, grp = dataset(dict(name="a", subjects=4), dict(name="b", subjects=4, start=50))
    _, r = run(emb, grp)
    text = str(r.to_dict())
    assert "a-0" not in text and "b-50" not in text


# ---------------------------------------------------------------- edge / misuse
def test_single_group_is_inconclusive_not_error():
    emb, grp = dataset(dict(name="only", subjects=6))
    d, _ = run(emb, grp)
    assert "BIAS-INSUFFICIENT-GROUPS" in d.rules_fired
    assert d.confidence == 0.0


@pytest.mark.parametrize("kw", [dict(threshold=2.0), dict(target_far=0.9),
                                dict(min_group_n=2), dict(min_group_n=True),
                                dict(threshold_source="client")])
def test_bad_parameters_rejected(kw):
    emb, grp = dataset(dict(name="a", subjects=4), dict(name="b", subjects=4, start=50))
    with pytest.raises(EngineError):
        run(emb, grp, **kw)


@pytest.mark.parametrize("label", ["<script>", "a" * 41, 7, "=cmd()"])
def test_bad_group_label_rejected(label):
    with pytest.raises(EngineError) as e:
        normalize_group(label)
    assert e.value.code == "CON-INVALID"


def test_group_labels_are_normalised():
    assert normalize_group("  Female/20s ") == "female/20s"
    assert normalize_group("") == UNDISCLOSED and normalize_group(None) == UNDISCLOSED


def test_empty_input_rejected():
    with pytest.raises(EngineError) as e:
        run({}, {})
    assert e.value.code == "DATA-INSUFFICIENT"


def test_invalid_vector_rejected():
    with pytest.raises(EngineError) as e:
        run({"a": [[float("nan"), 1.0]]}, {"a": "g"})
    assert e.value.code == "EMB-INVALID-VECTOR"


def test_deterministic():
    emb, grp = dataset(dict(name="a", subjects=6), dict(name="b", subjects=6, start=50))
    d1, r1 = run(emb, grp)
    d2, r2 = run(emb, grp)
    assert r1.to_dict() == r2.to_dict() and d1.reasons == d2.reasons