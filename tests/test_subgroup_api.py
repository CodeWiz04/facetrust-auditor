"""FR-4 API tests: authorization, validation, bias evidence, privacy, export.

Uses the full app (conftest `client` / `api` fixtures).

Evaluation-case mapping:
  T5  bias reporting           -> test_t5_*
  T6  consent controls         -> test_withdrawn_and_wrong_purpose_subjects_are_excluded
  T-final malformed / unauthorized / safe failure
                               -> test_unauthenticated_*, test_auditor_*, test_invalid_*,
                                  test_insufficient_*, test_rate_limit_*
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
AUDITOR = "auditor@example.com"
MODEL = "synthetic-test-64d"
AUDIT = "/api/v1/subgroups/audit"
LEGACY = "/api/v1/evaluations/bias"
POLICY = "/api/v1/threshold/policy"


# --------------------------------------------------------------------------- helpers
def seed(*groups, seed=11, dim=64, purpose="evaluation",
         consent=ConsentStatus.GRANTED.value) -> list[str]:
    """groups: dicts with name, subjects, per_subject=3, noise=0.35, shared=0.0."""
    rng = np.random.default_rng(seed)
    codes = []
    with SessionLocal() as db:
        for spec in groups:
            name, n = spec["name"], spec["subjects"]
            per, noise, shared = spec.get("per_subject", 3), spec.get("noise", 0.35), spec.get("shared", 0.0)
            common = rng.normal(size=dim)
            for s in range(n):
                code = f"G-{seed}-{name.replace('/', '_')}-{s:03d}"
                sub = Subject(subject_code=code, consent_status=consent, consent_date="2026-11-01",
                              purpose=purpose, group=name)
                db.add(sub)
                db.flush()
                base = rng.normal(size=dim) + shared * common
                for k in range(per):
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
                        image_id=img.id, subject_id=sub.id, model_name=MODEL,
                        model_version="1.0.0", encrypted_embedding=encrypt_embedding(vec),
                        vector_dim=dim,
                    ))
                codes.append(code)
        db.commit()
    return codes


def biased():
    return seed(dict(name="clear", subjects=35, noise=0.3),
                dict(name="noisy", subjects=35, noise=1.4))


def balanced():
    return seed(dict(name="a", subjects=35), dict(name="b", subjects=35))


def audit_events(event: str) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.event == event).order_by(AuditLog.seq)
        ).all()
        return [json.loads(r.payload_json) | {"_role": r.actor_role} for r in rows]


@pytest.fixture()
def admin(api: ApiHelper) -> ApiHelper:
    api.register_and_login(ADMIN)
    return api


def run_audit(h: ApiHelper, path=AUDIT, **body):
    return h.client.post(path, json={"model_name": MODEL, **body}, headers=h.csrf_headers())


# --------------------------------------------------------------------------- authz
def test_unauthenticated_is_rejected(client: TestClient):
    for path in (AUDIT, LEGACY):
        r = client.post(path, json={"model_name": MODEL})
        assert r.status_code == 401
        assert r.json()["error_code"] == "AUTH-SESSION-INVALID"
    assert client.get("/api/v1/subgroups/runs").status_code == 401
    assert client.get("/api/v1/subgroups/groups").status_code == 401


def test_missing_csrf_is_rejected(admin: ApiHelper):
    for path in (AUDIT, LEGACY):
        r = admin.client.post(path, json={"model_name": MODEL})
        assert r.status_code == 403
        assert r.json()["error_code"] == "AUTH-CSRF-INVALID"


def test_auditor_cannot_run_but_can_read_and_denial_is_audited(admin: ApiHelper):
    balanced()
    created = admin.register(AUDITOR).json()
    r = admin.client.patch(f"/api/v1/users/{created['id']}/role", json={"role": "auditor"},
                           headers=admin.csrf_headers())
    assert r.status_code == 200
    assert run_audit(admin).status_code == 200          # admin creates one run

    with TestClient(app) as c:
        auditor = ApiHelper(c)
        assert auditor.login(AUDITOR).status_code == 200
        denied = run_audit(auditor)
        assert denied.status_code == 403
        assert denied.json()["error_code"] == "AUTH-FORBIDDEN"
        assert "subgroups" not in denied.json()
        assert auditor.client.get("/api/v1/subgroups/runs").json()["total"] == 1
        assert auditor.client.get("/api/v1/subgroups/groups").status_code == 200

    actions = [e["action"] for e in audit_events("ACCESS_DENIED")]
    assert "subgroup.audit" in actions


# --------------------------------------------------------------------------- validation
@pytest.mark.parametrize("body", [
    {"model_name": "../../etc/passwd"},
    {"model_name": MODEL, "operating_threshold": 2},
    {"model_name": MODEL, "operating_threshold": "high"},
    {"model_name": MODEL, "group": "a"},                    # unknown field
])
def test_invalid_input_rejected(admin: ApiHelper, body):
    r = admin.client.post(AUDIT, json=body, headers=admin.csrf_headers())
    assert r.status_code == 422
    assert r.json()["error_code"] == "VALIDATION-FAILED"
    assert "Traceback" not in r.text


def test_insufficient_data_is_safe_and_audited(admin: ApiHelper):
    r = run_audit(admin)
    assert r.status_code == 400
    assert r.json()["error_code"] == "EVAL-INSUFFICIENT-DATA"
    assert audit_events("EVALUATION_BIAS_FAILED")[-1]["error_code"] == "EVAL-INSUFFICIENT-DATA"


# --------------------------------------------------------------------------- T5
@pytest.mark.parametrize("path", [AUDIT, LEGACY])
def test_t5_disparity_is_flagged_with_named_rule(admin: ApiHelper, path):
    codes = biased()
    r = run_audit(admin, path=path)
    assert r.status_code == 200, r.text
    d = r.json()

    # original response fields still present
    for key in ("run_id", "operating_threshold", "subgroups", "max_far_gap", "max_frr_gap",
                "disparity_ratio", "summary", "decision"):
        assert key in d

    assert d["status"] == "flagged" and d["severity"] == "high"
    assert "BIAS-FRR-DISPARITY" in d["rules_fired"]
    assert d["frr_comparison"]["worst_group"] == "noisy"
    assert d["frr_comparison"]["significant"] is True
    assert d["decision"]["stage"] == "subgroup"
    assert d["threshold_source"] == "policy" and d["operating_threshold"] == 0.5
    groups = {g["group"]: g for g in d["subgroups"]}
    assert groups["noisy"]["frr"] > groups["clear"]["frr"]
    assert groups["noisy"]["sample_count"] == 35
    assert groups["noisy"]["frr_ci95"][0] > groups["clear"]["frr_ci95"][1]
    assert any("noisy" in reason for reason in d["reasons"])

    detail = admin.client.get(f"/api/v1/subgroups/runs/{d['run_id']}")
    assert detail.status_code == 200
    assert all(code not in detail.text for code in codes)          # no subject identifiers
    assert audit_events("EVALUATION_BIAS_COMPLETED")[-1]["run_id"] == d["run_id"]


def test_t5_balanced_groups_complete(admin: ApiHelper):
    balanced()
    d = run_audit(admin).json()
    assert d["status"] == "completed", d["reasons"]
    assert d["rules_fired"] == []
    assert set(d["eligible_groups"]) == {"a", "b"}
    assert d["confidence"] == 1.0


def test_t5_uses_active_policy_threshold_and_records_override(admin: ApiHelper):
    balanced()
    r = admin.client.patch(POLICY, json={"match_threshold": 0.66, "reason": "fr4 test",
                                         "confirm": True}, headers=admin.csrf_headers())
    assert r.status_code == 200
    d = run_audit(admin).json()
    assert d["operating_threshold"] == 0.66 and d["threshold_source"] == "policy"
    assert d["policy_version"] == 2

    o = run_audit(admin, operating_threshold=0.4).json()
    assert o["operating_threshold"] == 0.4 and o["threshold_source"] == "override"
    assert audit_events("EVALUATION_BIAS_COMPLETED")[-1]["threshold_source"] == "override"


# --------------------------------------------------------------------------- privacy / consent
def test_small_group_is_suppressed_everywhere(admin: ApiHelper):
    seed(dict(name="a", subjects=6), dict(name="b", subjects=6), dict(name="tiny", subjects=2))
    d = run_audit(admin).json()
    tiny = next(g for g in d["subgroups"] if g["group"] == "tiny")
    assert tiny["status"] == "suppressed"
    assert tiny["frr"] is None and tiny["far"] is None and tiny["genuine_summary"] == {}
    assert d["suppressed_groups"] == 1
    assert "BIAS-LOW-SAMPLE" in d["rules_fired"]                    # 6 < min_group_n 30

    overview = admin.client.get("/api/v1/subgroups/groups").json()["items"]
    t = next(i for i in overview if i["group"] == "tiny")
    assert t["suppressed"] is True and t["subjects"] is None


def test_withdrawn_and_wrong_purpose_subjects_are_excluded(admin: ApiHelper):
    seed(dict(name="a", subjects=5), dict(name="b", subjects=5), seed=1)
    seed(dict(name="withdrawn", subjects=5), seed=2, consent=ConsentStatus.WITHDRAWN.value)
    seed(dict(name="tuning_only", subjects=5), seed=3, purpose="threshold_tuning")
    d = run_audit(admin).json()
    assert {g["group"] for g in d["subgroups"]} == {"a", "b"}
    overview = {i["group"] for i in admin.client.get("/api/v1/subgroups/groups").json()["items"]}
    assert overview == {"a", "b"}


def test_single_comparable_group_is_inconclusive(admin: ApiHelper):
    seed(dict(name="only", subjects=6))
    d = run_audit(admin).json()
    assert d["status"] == "flagged"
    assert "BIAS-INSUFFICIENT-GROUPS" in d["rules_fired"]


# --------------------------------------------------------------------------- history / export
def test_history_filter_and_export(admin: ApiHelper):
    codes = biased()
    run_id = run_audit(admin).json()["run_id"]

    flagged = admin.client.get("/api/v1/subgroups/runs?status=flagged").json()
    assert flagged["total"] == 1 and flagged["items"][0]["run_id"] == run_id
    assert admin.client.get("/api/v1/subgroups/runs?status=completed").json()["total"] == 0
    assert admin.client.get("/api/v1/subgroups/runs?status=x;DROP").status_code == 422

    j = admin.client.get(f"/api/v1/subgroups/runs/{run_id}/export?format=json")
    assert j.status_code == 200 and j.json()["report_type"] == "facetrust.fr4.subgroup_metrics"
    assert all(code not in j.text for code in codes)

    c = admin.client.get(f"/api/v1/subgroups/runs/{run_id}/export?format=csv")
    lines = c.text.strip().splitlines()
    assert lines[0].startswith("group,status,eligible,subjects")
    assert len(lines) == 1 + 2
    assert "attachment" in c.headers["content-disposition"]

    assert admin.client.get(f"/api/v1/subgroups/runs/{run_id}/export?format=pdf").status_code == 422
    assert len(audit_events("REPORT_EXPORTED")) == 2


def test_threshold_run_is_not_exposed_as_subgroup_run(admin: ApiHelper):
    balanced()
    t = admin.client.post("/api/v1/threshold/evaluate", json={"model_name": MODEL},
                          headers=admin.csrf_headers())
    assert t.status_code == 200
    r = admin.client.get(f"/api/v1/subgroups/runs/{t.json()['run_id']}")
    assert r.status_code == 409
    assert r.json()["error_code"] == "EVAL-RUN-TYPE-MISMATCH"


def test_rate_limit_on_audit(admin: ApiHelper):
    codes = [run_audit(admin).status_code for _ in range(11)]
    assert codes[:10] == [400] * 10 and codes[10] == 429