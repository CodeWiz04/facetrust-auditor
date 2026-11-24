# FR-3 — Threshold Tuning

FR-3 measures how the stored face embeddings of **consented** subjects separate
into *genuine* pairs (same person) and *impostor* pairs (different people). It
reports false accept and false reject rates at the active threshold, recommends a
threshold for a target false accept rate (FAR), and lets an administrator apply
that threshold. Every change is versioned and audited.

Decision rule everywhere: **ACCEPT if cosine score ≥ threshold**.

| Term | Meaning |
|---|---|
| FAR | impostor pairs accepted ÷ impostor pairs |
| FRR | genuine pairs rejected ÷ genuine pairs |
| EER | error rate where FAR = FRR (interpolated) |
| Target band | all thresholds that meet the target FAR with the lowest possible FRR |
| Recommended threshold | middle of the target band (keeps the best FRR and adds margin on both sides) |

## 1. Where the code lives (layered architecture)

| Layer | File | Role |
|---|---|---|
| 3 Security engine | `engine/threshold.py` | Pure numpy: pair scoring, FAR/FRR + Wilson 95% CI, curve, EER, recommendation, named rules, `Decision` |
| 4 Repository | `app/models/policy.py` | Append-only `policy_versions` table (one row per threshold change) |
| 2 Service | `app/services/policy_service.py` | Load/verify active policy (hash check), apply changes, `CONFIG_CHANGED` audit |
| 2 Service | `app/services/threshold_service.py` | Consent and purpose filtering, decryption in memory, persisting aggregate evidence only, export, apply-run |
| 2 API | `app/api/v1/thresholds.py` | Endpoints, RBAC, CSRF, rate limits, confirmation |
| 2 API | `app/api/v1/evaluations.py` | `POST /evaluations/threshold` kept for existing clients (now authenticated) |
| 5 Fixtures | `scripts/seed_threshold_demo.py` | Synthetic consented subjects; no real faces |

FR-4 (bias audit) and FR-5 (liveness) now read the **active stored policy**
instead of `defaults.json`, so a threshold an admin applies here is the one the
subgroup metrics use in the next stage.

## 2. API

All routes are under `/api/v1`. State-changing routes need the `X-CSRF-Token`
header returned by login.

| Method & path | Roles | Notes |
|---|---|---|
| `POST /threshold/evaluate` | admin, analyst | body: `model_name`, optional `model_version`, `target_far`, `threshold_steps`. Rate limit 10/min/user |
| `POST /evaluations/threshold` | admin, analyst | Same as above (backward compatible) |
| `GET /threshold/policy` | admin, analyst, auditor | Active threshold, target FAR, version, config hash |
| `GET /threshold/policy/history` | admin, auditor | All versions with old → new, reason, source run |
| `PATCH /threshold/policy` | admin | `{match_threshold?, target_far?, reason, confirm:true, expected_version?}` |
| `GET /threshold/runs?status=&model_name=` | admin, analyst, auditor | History and filters for the dashboard |
| `GET /threshold/runs/{id}` | admin, analyst, auditor | Decision, rules, operating points, score distributions, curve |
| `GET /threshold/runs/{id}/export?format=json\|csv` | admin, analyst, auditor | Sanitized report (aggregates only) |
| `POST /threshold/runs/{id}/apply` | admin | `{reason, confirm:true, acknowledge_low_confidence?, expected_version?}` |

### Named rules (never just "unsafe")

| Rule | Severity | Fires when |
|---|---|---|
| `THR-ACTIVE-FAR-EXCEEDS-TARGET` | high | Active threshold accepts more impostors than the target allows |
| `THR-TARGET-UNMET` | high | No threshold ≤ 1.0 reaches the target FAR |
| `THR-LOW-CONFIDENCE` | medium | Fewer than `3 / target_far` impostor pairs or fewer than 30 genuine pairs (rule of three) |
| `THR-RECOMMENDED-FRR-HIGH` | low | Recommended threshold rejects more than 20% of genuine attempts |

### Error codes added

`EVAL-DATA-INTEGRITY`, `EVAL-MODEL-VERSION-AMBIGUOUS`, `EVAL-RUN-TYPE-MISMATCH`,
`CFG-CONFIRMATION-REQUIRED`, `CFG-VERSION-CONFLICT`, `CFG-INTEGRITY`,
`THR-APPLY-BLOCKED`, `THR-LOW-CONFIDENCE-UNACKNOWLEDGED`. Responses only carry
`error_code`, `message` and `request_id`; there are no stack traces.

### Audit events added

`CONFIG_INITIALIZED`, `CONFIG_CHANGED`, `CONFIG_CHANGE_REJECTED`,
`EVALUATION_THRESHOLD_COMPLETED` (extended payload), `EVALUATION_THRESHOLD_FAILED`,
`REPORT_EXPORTED`, `ACCESS_DENIED`.

## 3. Install, configure and run

You need Python 3.10–3.12; 3.12 is recommended because dlib has no wheels for 3.13.

```bash
# from the repository root
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env            # Windows: copy .env.example .env
# edit .env: set SECRET_KEY and BIOMETRIC_ENCRYPTION_KEY (commands are in the file)
```

No new packages or `.env` keys are needed for FR-3. The new `policy_versions`
table is created automatically on startup (`AUTO_CREATE_TABLES=true`).

```bash
python scripts/seed_threshold_demo.py          # synthetic consented data
uvicorn app.main:app --reload --port 8000      # API + Swagger at http://localhost:8000/docs
```

Run the tests:

```bash
pytest tests/test_threshold_engine.py tests/test_threshold_api.py -v
pytest                                         # whole suite
pytest --cov=engine --cov=app --cov-report=term-missing
```

## 4. Demo script (about 5 minutes; covers T1, T2 and the "admin changes a threshold" example)

Bash / Git-Bash (on PowerShell, use `curl.exe` and put the JSON in single quotes):

```bash
B=http://localhost:8000/api/v1
# 1) first account becomes admin
curl -s -X POST $B/auth/register -H "Content-Type: application/json" \
  -d '{"email":"admin@lab.local","password":"CorrectHorseBattery1!"}'
CSRF=$(curl -s -c jar.txt -X POST $B/auth/login -H "Content-Type: application/json" \
  -d '{"email":"admin@lab.local","password":"CorrectHorseBattery1!"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['csrf_token'])")

# 2) T1/T2: evaluate (active threshold 0.5)
curl -s -b jar.txt -X POST $B/threshold/evaluate -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" -d '{"model_name":"synthetic-demo-128d"}' > run1.json
python -c "import json;d=json.load(open('run1.json'));print(d['status'],d['rules_fired']);print('\n'.join(d['reasons']))"

# 3) adverse case: admin loosens the threshold, re-run -> THR-ACTIVE-FAR-EXCEEDS-TARGET
curl -s -b jar.txt -X PATCH $B/threshold/policy -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"match_threshold":0.05,"reason":"demo: deliberately weak threshold","confirm":true}'
curl -s -b jar.txt -X POST $B/threshold/evaluate -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" -d '{"model_name":"synthetic-demo-128d"}' > run2.json
python -c "import json;d=json.load(open('run2.json'));print(d['status'],d['severity'],d['rules_fired'],d['recommended_action'])"

# 4) apply the recommendation from run2 (confirmed, audited, versioned)
RUN=$(python -c "import json;print(json.load(open('run2.json'))['run_id'])")
curl -s -b jar.txt -X POST $B/threshold/runs/$RUN/apply -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" -d '{"reason":"apply FR-3 recommendation","confirm":true}'

# 5) traceability: history, audit chain, export
curl -s -b jar.txt $B/threshold/policy/history
curl -s -b jar.txt "$B/audit/events?limit=50"
curl -s -b jar.txt $B/audit/verify
curl -s -b jar.txt -o run2.csv "$B/threshold/runs/$RUN/export?format=csv"
```

For a harder dataset where the default threshold 0.5 rejects most genuine
users, run `python scripts/seed_threshold_demo.py --noise 1.3` and evaluate again.

To demonstrate an unauthorized request, register a second user (they become an
analyst) and call `PATCH /threshold/policy` as that user. The response is a generic
`403 AUTH-FORBIDDEN`, and an `ACCESS_DENIED` entry is written to the audit log.

## 5. Security decisions (threat → mitigation)

| Threat | Mitigation |
|---|---|
| Unauthorized threshold change | Admin-only, server-side RBAC, CSRF, `confirm:true`, reason, rate limit |
| Silent weakening of security | Append-only policy versions with hash; `CONFIG_CHANGED` audit entry with old → new and the source run |
| Tampered stored policy | Hash re-checked on every load; mismatch fails closed with `CFG-INTEGRITY` |
| Lost update / race | `expected_version` optimistic lock plus a unique version column → `CFG-VERSION-CONFLICT` |
| Over-confident claims on tiny data | Wilson 95% intervals, `THR-LOW-CONFIDENCE`; applying a low-confidence run needs explicit acknowledgement |
| Applying stale evidence | Apply is blocked if the run's target FAR differs from the active policy or the run predates FR-3 |
| Processing without consent | Only `GRANTED` subjects whose purpose is `evaluation` or `threshold_tuning` are used |
| Biometric leakage via results or exports | Only aggregates are stored and exported; vectors are decrypted in memory and dropped |
| Client-injected evidence | Active threshold always comes from the server policy; extra request fields are rejected |
| Mixed model versions | Different model versions are refused unless `model_version` is given |
| Resource exhaustion | Embedding cap (20k), seeded uniform impostor sampling (200k pairs), steps 10–500, rate limit |
| Probing by unauthorized users | Generic 403; `ACCESS_DENIED` is audited without exposing records |

## 6. Limitations

- One global threshold for all models. Run evaluations per model and apply the
  recommendation for the model you deploy.
- The rate limiter runs in-process and only suits a single-worker lab deployment.
- The synthetic demo data checks the pipeline, not real-world accuracy. Use real
  consented `dlib-resnet-128d` embeddings from FR-2 for the report numbers.