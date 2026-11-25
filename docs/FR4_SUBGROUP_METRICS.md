# FR-4: Subgroup Metrics (Demographic Bias Audit)

FR-4 checks whether the face matcher works equally well for every
self-reported demographic group. It uses the threshold the system actually
runs with: the active FR-3 policy. For each group it reports:

| Metric | Meaning |
|---|---|
| FRR | Share of the group's genuine pairs (same person) that are rejected |
| FAR | Share of same-group impostor pairs (two different people, both in the group) that are accepted. Same-group impostors are the hardest case. NIST FRVT demographic reports use this measure. |
| cross-group FAR | Impostor pairs between the group and everyone else (context only) |
| 95% CI | Wilson interval for each rate |
| group threshold for target | Threshold this group alone would need to meet the target FAR |

## How a decision is made (explainable, never just "biased")

A gap only counts as disparity when two conditions hold. The gap must be larger
than a tolerance, and the difference must be statistically supported: the worst
group's 95% CI must lie completely above the best group's.

| Rule | Severity | Fires when |
|---|---|---|
| `BIAS-FRR-DISPARITY` | high | The FRR gap is above 5 percentage points and the CIs don't overlap |
| `BIAS-FAR-DISPARITY` | high | The FAR gap is above the target FAR and the CIs don't overlap |
| `BIAS-GROUP-FAR-EXCEEDS-TARGET` | high | A group's FAR is above the target even at its lower 95% bound |
| `BIAS-FRR-GAP-UNCONFIRMED` / `BIAS-FAR-GAP-UNCONFIRMED` | low | The gap is above tolerance but the CIs overlap. Collect more data. |
| `BIAS-LOW-SAMPLE` | medium | A compared group has fewer than `min_group_n` subjects (policy, default 30) |
| `BIAS-INSUFFICIENT-GROUPS` | medium | Fewer than 2 groups can be compared |

Every rule carries a reason that names the groups and rates involved. The run
also stores a recommended action.

**Privacy rules**
- Groups with fewer than 3 subjects are suppressed: counts only, no rates. A
  rate computed for 1–2 people is effectively their own biometric result.
- `undisclosed` is reported but never used for comparisons.
- Only subjects whose consent is `granted` and whose purpose is `evaluation` or
  `bias_audit` are included.
- Stored results and exports contain aggregates only: no subject IDs and no
  embeddings.

## Files

| Layer | File |
|---|---|
| Security engine | `engine/subgroup.py` (pure numpy) |
| Service | `app/services/subgroup_service.py` |
| API | `app/api/v1/subgroups.py`, plus `POST /evaluations/bias`, kept for existing clients |
| Schemas | `app/schemas/evaluation.py` (request/response), `app/schemas/subgroup.py` (history, groups) |
| Tests | `tests/test_subgroup_engine.py`, `tests/test_subgroup_api.py` |

## API (`/api/v1`)

| Method & path | Roles | Notes |
|---|---|---|
| `POST /subgroups/audit` | admin, analyst | body: `model_name`, optional `model_version`, `operating_threshold` (what-if, recorded as `override`). CSRF required. Rate limit 10/min/user |
| `POST /evaluations/bias` | admin, analyst | Same as above (backward compatible) |
| `GET /subgroups/groups` | all roles | Subjects per group; groups with fewer than 3 subjects are hidden |
| `GET /subgroups/runs?status=&model_name=` | all roles | History and filters |
| `GET /subgroups/runs/{id}` | all roles | Per-group evidence, decision, rules |
| `GET /subgroups/runs/{id}/export?format=json\|csv` | all roles | Sanitized report (audited as `REPORT_EXPORTED`) |

Audit events: `EVALUATION_BIAS_COMPLETED`, `EVALUATION_BIAS_FAILED`, `ACCESS_DENIED`, `REPORT_EXPORTED`.

## Run it

```bash
python scripts/seed_threshold_demo.py --bias   # 96 synthetic subjects; group_c gets noisier samples
uvicorn app.main:app --reload --port 8000
pytest tests/test_subgroup_engine.py tests/test_subgroup_api.py -v
```

In Swagger (`/docs`), log in, copy `csrf_token`, then call `POST /api/v1/subgroups/audit`
with `{"model_name": "synthetic-demo-128d"}` and the `X-CSRF-Token` header.

Expected result: `status: "flagged"`, `BIAS-FRR-DISPARITY`, with `group_c` as the worst group.
Re-seed without `--bias` and run again: the result should be `completed` with no rules.

To show the pipeline link to FR-3: change the threshold with `PATCH /threshold/policy`,
then run the audit again. `operating_threshold` and `policy_version` follow the new policy.

## Limitations

- Group labels are self-reported and coarse. A result shows a difference
  between groups; it does not explain the cause (lighting, image quality, the
  model).
- The FRR tolerance (5 points) and the suppression size (3) are fixed engine
  constants. They are not admin settings, so nobody can relax them to hide a
  disparity. Change them only in code review.
- Synthetic demo data proves that the pipeline works. Use real consented FR-2
  embeddings for the numbers in the report.