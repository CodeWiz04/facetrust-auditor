"""FR-3 API tests: authorization, validation, evidence, policy changes, export.

Uses the full app (conftest `client` / `api` fixtures) so authentication,
CSRF, RBAC, rate limiting and the audit chain are exercised for real.

Evaluation-case mapping:
  T1  false accept/reject rates      -> test_evaluate_returns_explainable_evidence
  T2  threshold curves               -> test_evaluate_returns_explainable_evidence, test_export_*
  T6  consent controls               -> test_withdrawn_or_wrong_purpose_subjects_are_excluded
  T-final malformed / unauthorized / repeated / safe failure
                                     -> test_unauthenticated_*, test_*_forbidden_*,
                                        test_invalid_input_*, test_repeated_policy_change_*,
                                        test_rate_limit_*, test_policy_survives_*
"""

from __future__ import annotations

import json

import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.crypto import encrypt_embedding
from app.db.session import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.dataset import BiometricEmbedding, ConsentStatus, Subject, SubjectImage
from tests.conftest import ApiHelper

ADMIN = "admin@example.com"
ANALYST = "analyst@example.com"
AUDITOR = "auditor@example.com"
MODEL = "synthetic-test-64d"
EVAL = "/api/v1/threshold/evaluate"
LEGACY_EVAL = "/api/v1/evaluations/threshold"
POLICY = "/api/v1/threshold/policy"


# --------------------------------------------------------------------------- helpers
def seed_subjects(subjects=12, per_subject=4, dim=64, noise=0.35, seed=1,
                  consent=ConsentStatus.GRANTED.value, purpose="evaluation",
                  prefix="SUB", model=MODEL) -> list[str]:
    """Synthetic consented subjects with encrypted embeddings (no real faces)."""
    rng = np.random.default_rng(seed)
    codes = []
    with SessionLocal() as db:
        for s in range(subjects):
            code = f"{prefix}-{seed}-{s:03d}"
            sub = Subject(subject_code=code, consent_status=consent,
                          consent_date="2026-11-01", purpose=purpose, group="synthetic")
            db.add(sub)
            db.flush()
            base = rng.normal(size=dim)
            for k in range(per_subject):
                img = SubjectImage(
                    subject_id=sub.id, original_filename=f"{code}_{k}.png",
                    input_hash=f"sha256:{code}{k}", clean_hash=f"sha256:c{code}{k}",
                    storage_path=f"{sub.id}_{k}.enc", width=150, height=150,
                    detected_type="png",
                )
                db.add(img)
                db.flush()
                vec = (base + rng.normal(scale=noise, size=dim)).tolist()
                db.add(BiometricEmbedding(
                    image_id=img.id, subject_id=sub.id, model_name=model,
                    model_version="1.0.0", encrypted_embedding=encrypt_embedding(vec),
                    vector_dim=dim,
                ))
            codes.append(code)
        db.commit()
    return codes


def audit_events(event: str) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.event == event).order_by(AuditLog.seq)
        ).all()
        return [json.loads(r.payload_json) | {"_role": r.actor_role} for r in rows]


def promote(api: ApiHelper, user_id: str, role: str) -> None:
    r = api.client.patch(f"/api/v1/users/{user_id}/role", json={"role": role},
                         headers=api.csrf_headers())
    assert r.status_code == 200, r.text


@pytest.fixture()
def admin(api: ApiHelper) -> ApiHelper:
    api.register_and_login(ADMIN)
    return api


def other_user(admin: ApiHelper, email: str, role: str | None = None):
    """Register another user (optionally promoted) and return (client, helper)."""
    created = admin.register(email).json()
    if role:
        promote(admin, created["id"], role)
    c = TestClient(app)
    c.__enter__()
    h = ApiHelper(c)
    assert h.login(email).status_code == 200
    return c, h


def evaluate(h: ApiHelper, path=EVAL, **body):
    payload = {"model_name": MODEL, **body}
    return h.client.post(path, json=payload, headers=h.csrf_headers())


# --------------------------------------------------------------------------- authz
def test_unauthenticated_evaluate_is_rejected(client: TestClient):
    for path in (EVAL, LEGACY_EVAL):
        r = client.post(path, json={"model_name": MODEL})
        assert r.status_code == 401
        assert r.json()["error_code"] == "AUTH-SESSION-INVALID"
    assert client.get(POLICY).status_code == 401


def test_missing_csrf_is_rejected(admin: ApiHelper):
    r = admin.client.post(EVAL, json={"model_name": MODEL})
    assert r.status_code == 403
    assert r.json()["error_code"] == "AUTH-CSRF-INVALID"


def test_auditor_forbidden_to_run_or_change_and_attempt_is_audited(admin: ApiHelper):
    seed_subjects()
    c, auditor = other_user(admin, AUDITOR, "auditor")
    try:
        r = evaluate(auditor)
        assert r.status_code == 403
        body = r.json()
        assert body["error_code"] == "AUTH-FORBIDDEN"
        assert "run_id" not in body and "eer" not in body     # generic denial only

        r = auditor.client.patch(POLICY, json={"match_threshold": 0.9, "reason": "trying it",
                                               "confirm": True}, headers=auditor.csrf_headers())
        assert r.status_code == 403
        # auditor CAN read
        assert auditor.client.get(POLICY).status_code == 200
        assert auditor.client.get(POLICY + "/history").status_code == 200
    finally:
        c.__exit__(None, None, None)

    denied = audit_events("ACCESS_DENIED")
    actions = {d["action"] for d in denied}
    assert {"threshold.evaluate", "threshold.policy_change"} <= actions
    assert all(d["_role"] == "auditor" for d in denied)


def test_analyst_can_run_but_not_change_policy(admin: ApiHelper):
    seed_subjects()
    c, analyst = other_user(admin, ANALYST)
    try:
        assert evaluate(analyst).status_code == 200
        r = analyst.client.patch(POLICY, json={"match_threshold": 0.6, "reason": "analyst try",
                                               "confirm": True}, headers=analyst.csrf_headers())
        assert r.status_code == 403
        assert analyst.client.get(POLICY + "/history").status_code == 403
    finally:
        c.__exit__(None, None, None)


# --------------------------------------------------------------------------- validation
@pytest.mark.parametrize("body", [
    {"model_name": "../../etc/passwd"},
    {"model_name": MODEL, "target_far": 0.9},
    {"model_name": MODEL, "target_far": 0},
    {"model_name": MODEL, "threshold_steps": 5},
    {"model_name": MODEL, "threshold_steps": 100000},
    {"model_name": MODEL, "active_threshold": 0.1},          # client cannot inject it
    {"model_name": "x" * 200},
])
def test_invalid_input_is_rejected_with_safe_error(admin: ApiHelper, body):
    r = admin.client.post(EVAL, json=body, headers=admin.csrf_headers())
    assert r.status_code == 422
    data = r.json()
    assert data["error_code"] == "VALIDATION-FAILED"
    assert "Traceback" not in r.text


def test_insufficient_data_is_a_safe_audited_failure(admin: ApiHelper):
    r = evaluate(admin)
    assert r.status_code == 400
    assert r.json()["error_code"] == "EVAL-INSUFFICIENT-DATA"
    failed = audit_events("EVALUATION_THRESHOLD_FAILED")
    assert failed and failed[-1]["error_code"] == "EVAL-INSUFFICIENT-DATA"


# --------------------------------------------------------------------------- evidence (T1/T2)
@pytest.mark.parametrize("path", [EVAL, LEGACY_EVAL])
def test_evaluate_returns_explainable_evidence(admin: ApiHelper, path):
    codes = seed_subjects(subjects=12, per_subject=4)
    r = evaluate(admin, path=path, threshold_steps=40)
    assert r.status_code == 200, r.text
    d = r.json()

    # original response fields still present
    for key in ("run_id", "operating_threshold", "far_at_threshold", "frr_at_threshold",
                "eer", "eer_threshold", "total_genuine_pairs", "total_impostor_pairs",
                "roc_curve", "decision"):
        assert key in d
    assert d["total_genuine_pairs"] == 12 * 6
    assert d["total_impostor_pairs"] == (48 * 48 - 12 * 16) // 2
    assert len(d["roc_curve"]) == 40

    # FR-3 evidence
    assert d["policy_version"] == 1
    assert d["active"]["threshold"] == 0.5                     # from stored policy
    assert d["recommended"]["far"] <= d["target_far"] == 0.01
    assert d["target_met"] is True
    assert d["decision"]["stage"] == "threshold"
    assert d["decision"]["config_hash"] == d["config_hash"]
    assert d["reasons"] and d["recommended_action"]
    assert d["status"] in ("completed", "flagged")
    if d["status"] == "flagged":
        assert d["rules_fired"]                               # never a bare "unsafe"

    # stored evidence has no identifiers / vectors
    detail = admin.client.get(f"/api/v1/threshold/runs/{d['run_id']}")
    assert detail.status_code == 200
    text = detail.text
    assert all(code not in text for code in codes)
    assert set(detail.json()["operating_points"]) == {"active", "recommended"}

    completed = audit_events("EVALUATION_THRESHOLD_COMPLETED")
    assert completed[-1]["run_id"] == d["run_id"]
    assert completed[-1]["policy_version"] == 1


def test_withdrawn_or_wrong_purpose_subjects_are_excluded(admin: ApiHelper):
    seed_subjects(subjects=6, per_subject=3, seed=1)
    seed_subjects(subjects=4, per_subject=3, seed=2, consent=ConsentStatus.WITHDRAWN.value)
    seed_subjects(subjects=4, per_subject=3, seed=3, purpose="bias_audit")
    r = evaluate(admin)
    assert r.status_code == 200, r.text
    assert r.json()["subjects"] == 6


def test_low_sample_is_flagged_low_confidence(admin: ApiHelper):
    seed_subjects(subjects=3, per_subject=2)
    d = evaluate(admin).json()
    assert d["status"] == "flagged"
    assert "THR-LOW-CONFIDENCE" in d["rules_fired"]
    assert d["confidence"] < 1


# --------------------------------------------------------------------------- policy changes
def test_policy_change_requires_confirmation_and_is_traceable(admin: ApiHelper):
    before = admin.client.get(POLICY).json()
    assert before["version"] == 1 and before["match_threshold"] == 0.5

    no_confirm = admin.client.patch(POLICY, json={"match_threshold": 0.62, "reason": "tighten"},
                                    headers=admin.csrf_headers())
    assert no_confirm.status_code == 400
    assert no_confirm.json()["error_code"] == "CFG-CONFIRMATION-REQUIRED"

    ok = admin.client.patch(POLICY, json={"match_threshold": 0.62, "reason": "tighten for demo",
                                          "confirm": True, "expected_version": 1},
                            headers=admin.csrf_headers())
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["changed"] is True
    assert body["policy"]["version"] == 2
    assert body["changes"] == [{"key": "match_threshold", "old": 0.5, "new": 0.62}]
    assert body["policy"]["config_hash"] != before["config_hash"]

    changed = audit_events("CONFIG_CHANGED")
    assert changed[-1]["changes"][0]["new"] == 0.62
    assert changed[-1]["version_from"] == 1 and changed[-1]["version_to"] == 2
    assert changed[-1]["reason"] == "tighten for demo"

    history = admin.client.get(POLICY + "/history").json()
    assert history["total"] == 2 and history["items"][0]["version"] == 2


def test_repeated_policy_change_is_idempotent_and_stale_version_conflicts(admin: ApiHelper):
    body = {"match_threshold": 0.7, "reason": "set to 0.7", "confirm": True}
    assert admin.client.patch(POLICY, json=body, headers=admin.csrf_headers()).json()["changed"]
    again = admin.client.patch(POLICY, json=body, headers=admin.csrf_headers()).json()
    assert again["changed"] is False and again["policy"]["version"] == 2

    stale = admin.client.patch(POLICY, json=body | {"expected_version": 1, "match_threshold": 0.8},
                               headers=admin.csrf_headers())
    assert stale.status_code == 409
    assert stale.json()["error_code"] == "CFG-VERSION-CONFLICT"


@pytest.mark.parametrize("body", [
    {"match_threshold": 1.5, "reason": "out of range", "confirm": True},
    {"match_threshold": "high", "reason": "wrong type", "confirm": True},
    {"reason": "nothing to change", "confirm": True},
    {"match_threshold": 0.6, "reason": "x", "confirm": True},              # reason too short
    {"match_threshold": 0.6, "reason": "ok reason", "confirm": True, "liveness.blur_min": 1},
])
def test_invalid_policy_change_rejected(admin: ApiHelper, body):
    r = admin.client.patch(POLICY, json=body, headers=admin.csrf_headers())
    assert r.status_code == 422
    assert admin.client.get(POLICY).json()["version"] == 1


def test_apply_run_recommendation_then_rerun_shows_new_policy(admin: ApiHelper):
    seed_subjects(subjects=12, per_subject=4)
    run = evaluate(admin).json()
    rec = run["operating_threshold"]
    ack = "THR-LOW-CONFIDENCE" in run["rules_fired"]

    applied = admin.client.post(
        f"/api/v1/threshold/runs/{run['run_id']}/apply",
        json={"reason": "apply FR-3 recommendation", "confirm": True,
              "acknowledge_low_confidence": ack},
        headers=admin.csrf_headers(),
    )
    assert applied.status_code == 200, applied.text
    pol = applied.json()["policy"]
    assert pol["match_threshold"] == rec
    assert pol["source_run_id"] == run["run_id"]

    rerun = evaluate(admin).json()
    assert rerun["policy_version"] == pol["version"]
    assert rerun["active"]["threshold"] == rec
    assert rerun["config_hash"] == pol["config_hash"]
    assert "THR-ACTIVE-FAR-EXCEEDS-TARGET" not in rerun["rules_fired"]


def test_apply_low_confidence_run_needs_acknowledgement(admin: ApiHelper):
    seed_subjects(subjects=3, per_subject=2)
    run = evaluate(admin).json()
    assert "THR-LOW-CONFIDENCE" in run["rules_fired"]
    url = f"/api/v1/threshold/runs/{run['run_id']}/apply"
    r = admin.client.post(url, json={"reason": "apply small run", "confirm": True},
                          headers=admin.csrf_headers())
    assert r.status_code == 409
    assert r.json()["error_code"] == "THR-LOW-CONFIDENCE-UNACKNOWLEDGED"
    assert admin.client.get(POLICY).json()["version"] == 1


def test_apply_blocked_when_target_far_changed_since_run(admin: ApiHelper):
    seed_subjects()
    run = evaluate(admin).json()
    admin.client.patch(POLICY, json={"target_far": 0.05, "reason": "relax target",
                                     "confirm": True}, headers=admin.csrf_headers())
    r = admin.client.post(f"/api/v1/threshold/runs/{run['run_id']}/apply",
                          json={"reason": "apply old run", "confirm": True,
                                "acknowledge_low_confidence": True},
                          headers=admin.csrf_headers())
    assert r.status_code == 409
    assert r.json()["error_code"] == "THR-APPLY-BLOCKED"


def test_bias_audit_uses_active_threshold(admin: ApiHelper):
    seed_subjects()
    admin.client.patch(POLICY, json={"match_threshold": 0.66, "reason": "new threshold",
                                     "confirm": True}, headers=admin.csrf_headers())
    r = admin.client.post("/api/v1/evaluations/bias", json={"model_name": MODEL},
                          headers=admin.csrf_headers())
    assert r.status_code == 200, r.text
    assert r.json()["operating_threshold"] == 0.66


# --------------------------------------------------------------------------- history / export
def test_history_filter_and_export(admin: ApiHelper):
    codes = seed_subjects(subjects=3, per_subject=2)
    run = evaluate(admin).json()

    runs = admin.client.get("/api/v1/threshold/runs?status=flagged").json()
    assert runs["total"] == 1 and runs["items"][0]["run_id"] == run["run_id"]
    assert admin.client.get("/api/v1/threshold/runs?status=completed").json()["total"] == 0
    assert admin.client.get("/api/v1/threshold/runs?status=DROP").status_code == 422

    j = admin.client.get(f"/api/v1/threshold/runs/{run['run_id']}/export?format=json")
    assert j.status_code == 200
    assert j.headers["content-type"].startswith("application/json")
    assert "attachment" in j.headers["content-disposition"]
    assert all(code not in j.text for code in codes)
    assert j.json()["report_type"] == "facetrust.fr3.threshold_tuning"

    c = admin.client.get(f"/api/v1/threshold/runs/{run['run_id']}/export?format=csv")
    assert c.status_code == 200
    lines = c.text.strip().splitlines()
    assert lines[0] == "threshold,far,frr,tpr,genuine_matches,impostor_matches"
    assert len(lines) == 1 + 50

    assert admin.client.get(
        f"/api/v1/threshold/runs/{run['run_id']}/export?format=xml").status_code == 422
    assert admin.client.get("/api/v1/threshold/runs/nope/export").status_code == 404
    assert len(audit_events("REPORT_EXPORTED")) == 2


def test_non_threshold_run_is_not_exposed_as_threshold(admin: ApiHelper):
    import io

    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (150, 150), (120, 140, 160)).save(buf, format="PNG")
    live = admin.client.post("/api/v1/evaluations/liveness",
                             files={"file": ("x.png", buf.getvalue(), "image/png")})
    assert live.status_code == 200
    run_id = admin.client.get("/api/v1/evaluations?run_type=liveness").json()["items"][0]["id"]
    r = admin.client.get(f"/api/v1/threshold/runs/{run_id}")
    assert r.status_code == 409
    assert r.json()["error_code"] == "EVAL-RUN-TYPE-MISMATCH"


# --------------------------------------------------------------------------- abuse / recovery
def test_rate_limit_on_evaluation(admin: ApiHelper):
    codes = [evaluate(admin).status_code for _ in range(11)]
    assert codes[:10] == [400] * 10            # insufficient data, but allowed
    assert codes[10] == 429


def test_policy_survives_restart_and_tampering_is_detected(admin: ApiHelper):
    admin.client.patch(POLICY, json={"match_threshold": 0.58, "reason": "persist me",
                                     "confirm": True}, headers=admin.csrf_headers())
    # "restart": a brand-new client / app lifespan reads the same database
    with TestClient(app) as fresh:
        h = ApiHelper(fresh)
        assert h.login(ADMIN).status_code == 200
        assert h.client.get(POLICY).json()["match_threshold"] == 0.58

    from app.models.policy import PolicyVersion
    with SessionLocal() as db:
        row = db.scalars(select(PolicyVersion).order_by(PolicyVersion.version.desc())).first()
        row.config_json = row.config_json.replace("0.58", "0.01")   # tamper
        db.commit()
    r = admin.client.get(POLICY)
    assert r.status_code == 500
    assert r.json()["error_code"] == "CFG-INTEGRITY"
    assert "0.01" not in r.text