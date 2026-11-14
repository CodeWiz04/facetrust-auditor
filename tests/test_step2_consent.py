from datetime import date

import pytest

from engine.consent import (
    consent_decision,
    evaluate_manifest,
    parse_manifest,
    validate_consent_record,
)
from engine.errors import EngineError
from engine.hashing import config_hash
from engine.policy import load_default_config

CFG = load_default_config()
LIMITS = CFG["limits"]
CH = config_hash(CFG)
TODAY = date(2026, 11, 14)


def good(**over):
    rec = {
        "subject_id": "subj_001",
        "consent_given": True,
        "consent_date": "2026-09-01",
        "purpose": "evaluation",
        "image_file": "subj_001_a.png",
        "group": "Group A",
    }
    rec.update(over)
    return rec


def code_of(raw):
    with pytest.raises(EngineError) as ei:
        validate_consent_record(raw, TODAY)
    return ei.value.code


# ---------- positive ----------
def test_valid_record_is_normalized():
    rec = validate_consent_record(good(), TODAY)
    assert rec.group == "group a"
    assert rec.subject_id == "subj_001"


def test_group_is_optional_and_defaults_to_undisclosed():
    raw = good()
    del raw["group"]
    assert validate_consent_record(raw, TODAY).group == "undisclosed"


def test_decision_verified_has_reason_and_no_rules():
    d, rec = consent_decision(good(), CH, TODAY)
    assert d.status == "completed" and d.outcome == "CONSENT_VERIFIED"
    assert d.reasons and rec is not None


# ---------- negative: consent rules ----------
def test_consent_false_is_rejected_with_named_rule():
    d, rec = consent_decision(good(consent_given=False), CH, TODAY)
    assert d.status == "rejected" and rec is None
    assert d.rules_fired == ("CON-NOT-GRANTED",)
    assert d.severity == "high"


def test_missing_consent_field_is_rejected():
    raw = good()
    del raw["consent_given"]
    assert code_of(raw) == "CON-MISSING"


def test_withdrawn_consent_is_rejected():
    assert code_of(good(consent_withdrawn=True)) == "CON-WITHDRAWN"


@pytest.mark.parametrize("value", ["yes", "true", 1, 0, None])
def test_consent_must_be_a_real_boolean(value):
    assert code_of(good(consent_given=value)) == "CON-INVALID"


@pytest.mark.parametrize("raw", [None, {}, [], "text", 5])
def test_empty_or_wrong_type_record_is_missing(raw):
    assert code_of(raw) == "CON-MISSING"


# ---------- negative: field validation / misuse ----------
@pytest.mark.parametrize(
    "field,value",
    [
        ("subject_id", "x'; DROP TABLE users;--"),
        ("subject_id", "ab"),
        ("subject_id", "Real Name"),
        ("image_file", "../../etc/passwd"),
        ("image_file", "..\\secret.png"),
        ("image_file", "/abs/path.png"),
        ("image_file", ".hidden.png"),
        ("group", "<script>alert(1)</script>"),
    ],
)
def test_malicious_field_values_rejected(field, value):
    assert code_of(good(**{field: value})) == "CON-INVALID"


def test_unknown_field_rejected():
    assert code_of(good(is_admin=True)) == "CON-INVALID"


@pytest.mark.parametrize("value", ["2026-13-40", "01/09/2026", "20260901", "2027-01-01", 20260901])
def test_bad_or_future_date_rejected(value):
    assert code_of(good(consent_date=value)) == "CON-DATE-INVALID"


def test_purpose_not_allowed():
    assert code_of(good(purpose="marketing")) == "CON-PURPOSE-INVALID"


def test_rejection_reason_does_not_echo_input_value():
    payload = "x'; DROP TABLE users;--"
    d, _ = consent_decision(good(subject_id=payload), CH, TODAY)
    assert "DROP" not in " ".join(d.reasons)
    assert "DROP" not in d.input_ref


def test_decision_ref_is_stable_for_same_record():
    d1, _ = consent_decision(good(), CH, TODAY)
    d2, _ = consent_decision(good(), CH, TODAY)
    assert d1.input_ref == d2.input_ref
    assert d1.decision_id != d2.decision_id


# ---------- manifest ----------
HEADER = "subject_id,consent_given,consent_date,purpose,image_file,group\n"


def manifest(*lines):
    return (HEADER + "\n".join(lines) + "\n").encode()


def test_manifest_parses_and_checks_every_row():
    data = manifest(
        "subj_001,true,2026-09-01,evaluation,a.png,Group A",
        "subj_002,false,2026-09-01,evaluation,b.png,Group B",
        "subj_003,,2026-09-01,evaluation,c.png,Group B",
    )
    res = evaluate_manifest(data, LIMITS, CH, TODAY)
    assert [r[1].outcome for r in res] == [
        "CONSENT_VERIFIED", "CONSENT_REJECTED", "CONSENT_REJECTED"]
    assert res[1][1].rules_fired == ("CON-NOT-GRANTED",)
    assert res[2][1].rules_fired == ("CON-MISSING",)
    assert [r[0] for r in res] == [2, 3, 4]


def test_manifest_too_large_bytes():
    small = dict(LIMITS, max_manifest_bytes=50)
    with pytest.raises(EngineError) as ei:
        parse_manifest(manifest("subj_001,true,2026-09-01,evaluation,a.png,A"), small)
    assert ei.value.code == "MAN-TOO-LARGE"


def test_manifest_too_many_rows():
    small = dict(LIMITS, max_manifest_rows=1)
    data = manifest(
        "subj_001,true,2026-09-01,evaluation,a.png,A",
        "subj_002,true,2026-09-01,evaluation,b.png,A",
    )
    with pytest.raises(EngineError) as ei:
        parse_manifest(data, small)
    assert ei.value.code == "MAN-TOO-LARGE"


@pytest.mark.parametrize(
    "data",
    [
        b"subject_id,consent_given\nx,true\n",                                  # missing columns
        (HEADER.strip() + ",extra\n").encode(),                                 # unknown column
        manifest("subj_001,true,2026-09-01,evaluation"),                        # too few cells
        manifest("subj_001,true,2026-09-01,evaluation,a.png,A,zzz"),            # too many cells
        manifest("subj_001,true,2026-09-01,evaluation,a.png,A",
                 "subj_002,true,2026-09-01,evaluation,a.png,A"),                # duplicate file
        b"\xff\xfe\x00bad",                                                     # not UTF-8
    ],
)
def test_malformed_manifest_rejected(data):
    with pytest.raises(EngineError) as ei:
        parse_manifest(data, LIMITS)
    assert ei.value.code == "MAN-INVALID"


def test_manifest_accepts_utf8_bom():
    data = b"\xef\xbb\xbf" + manifest("subj_001,true,2026-09-01,evaluation,a.png,A")
    assert len(parse_manifest(data, LIMITS)) == 1