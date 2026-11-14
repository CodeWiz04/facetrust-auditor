import json
import math

import pytest

from engine.decision import Decision, Timer
from engine.errors import EngineError, ERROR_CATALOG
from engine.hashing import canonical_json, config_hash, hash_input
from engine.policy import load_default_config, update_config


# ---------- hashing ----------
def test_canonical_json_ignores_key_order():
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_config_hash_stable_under_key_reordering():
    cfg = load_default_config()
    reordered = {k: cfg[k] for k in reversed(list(cfg))}
    assert config_hash(cfg) == config_hash(reordered)


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_hash_input_is_prefixed_and_deterministic():
    assert hash_input(b"abc") == hash_input(b"abc")
    assert hash_input(b"abc").startswith("sha256:")
    assert hash_input(b"abc") != hash_input(b"abd")


# ---------- errors ----------
def test_unknown_error_code_falls_back_to_internal():
    e = EngineError("MADE-UP-CODE")
    assert e.code == "ENG-INTERNAL"


def test_error_dict_has_no_detail():
    e = EngineError("CFG-OUT-OF-RANGE", detail="secret-ish internals")
    d = e.to_dict()
    assert set(d) == {"error_code", "message"}
    assert "secret" not in json.dumps(d)
    assert e.code in ERROR_CATALOG


# ---------- policy ----------
def test_defaults_load_and_validate():
    cfg = load_default_config()
    assert cfg["config_version"] == 1


def test_update_changes_hash_version_and_records_old_new():
    cfg = load_default_config()
    new, records = update_config(cfg, {"match_threshold": 0.7})
    assert new["match_threshold"] == 0.7
    assert new["config_version"] == cfg["config_version"] + 1
    assert config_hash(new) != config_hash(cfg)
    assert records == [{"key": "match_threshold", "old": 0.5, "new": 0.7}]


def test_update_does_not_mutate_original():
    cfg = load_default_config()
    before = config_hash(cfg)
    update_config(cfg, {"liveness.blur_min": 150})
    assert config_hash(cfg) == before


def test_noop_update_does_not_bump_version():
    cfg = load_default_config()
    new, records = update_config(cfg, {"match_threshold": 0.5})
    assert records == []
    assert new["config_version"] == cfg["config_version"]


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"match_threshold": float("nan")}, "CFG-OUT-OF-RANGE"),
        ({"match_threshold": float("inf")}, "CFG-OUT-OF-RANGE"),
        ({"match_threshold": 5.0}, "CFG-OUT-OF-RANGE"),
        ({"match_threshold": "0.5"}, "CFG-INVALID-TYPE"),
        ({"match_threshold": True}, "CFG-INVALID-TYPE"),
        ({"min_group_n": 10.5}, "CFG-INVALID-TYPE"),
        ({"limits.max_image_bytes": 1}, "CFG-UNKNOWN-KEY"),
        ({"config_version": 99}, "CFG-UNKNOWN-KEY"),
        ({"not.a.key": 1}, "CFG-UNKNOWN-KEY"),
        ({"liveness.bright_min": 250.0}, "CFG-INCONSISTENT"),
    ],
)
def test_bad_updates_rejected_with_stable_codes(changes, code):
    cfg = load_default_config()
    with pytest.raises(EngineError) as ei:
        update_config(cfg, changes)
    assert ei.value.code == code


def test_failed_update_is_all_or_nothing():
    cfg = load_default_config()
    with pytest.raises(EngineError):
        update_config(cfg, {"match_threshold": 0.6, "target_far": 99})
    assert cfg["match_threshold"] == 0.5


# ---------- decision ----------
def _ok(**over):
    base = dict(
        stage="liveness",
        status="completed",
        outcome="LIVE",
        reasons=["No spoof cues fired."],
        config_hash="abc",
        input_ref=hash_input(b"img"),
        latency_ms=1.2,
    )
    base.update(over)
    return Decision.create(**base)


def test_decision_created_with_server_side_id_and_version():
    d = _ok()
    assert len(d.decision_id) == 36
    assert d.engine_version


def test_flagged_without_rule_is_rejected():
    with pytest.raises(EngineError):
        _ok(status="flagged", outcome="SUSPECTED_SPOOF", severity="high")


def test_decision_without_reasons_is_rejected():
    with pytest.raises(EngineError):
        _ok(reasons=[])


def test_flagged_with_rule_and_reason_is_valid_and_json_safe():
    d = _ok(
        status="flagged",
        outcome="SUSPECTED_SPOOF",
        severity="high",
        rules_fired=["LIV-MOIRE-HIGH"],
        reasons=["High-frequency ratio 0.91 exceeds limit 0.85."],
    )
    json.dumps(d.to_dict())  # must not raise


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_non_finite_score_rejected(bad):
    with pytest.raises(EngineError):
        _ok(score=bad)


def test_confidence_range_enforced():
    with pytest.raises(EngineError):
        _ok(confidence=1.5)


def test_invalid_stage_status_severity_rejected():
    for over in ({"stage": "x"}, {"status": "x"}, {"severity": "x"}):
        with pytest.raises(EngineError):
            _ok(**over)


def test_decision_is_immutable():
    d = _ok()
    with pytest.raises(Exception):
        d.outcome = "HACKED"


def test_timer_returns_non_negative_ms():
    assert Timer().ms() >= 0