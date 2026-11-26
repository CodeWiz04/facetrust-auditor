# FR-6: Privacy-Preserving Deletion & Forensic Erasure

FR-6 implements the Right-to-be-Forgotten and complete lifecycle privacy controls for biometric data. It guarantees that when a subject withdraws consent or requests deletion, all identifiable records, raw encrypted image files, and derived embedding vectors are irreversibly purged with zero sensitive residual data.

## Objectives & Privacy Guarantees

1. **Forensic Physical Erasure (NIST SP 800-88 Rev 1)**:
   - Biometric face files are not simply unlinked (`rm`), but forensically overwritten before unlinking:
     - **Pass 1**: Overwrite with cryptographic pseudo-random bytes (`os.urandom`).
     - **Pass 2**: Zeroization (all `0x00` bytes).
     - **Truncation**: Truncated to 0 bytes and flushed to physical storage media (`fsync`).
     - **Post-deletion verification**: Filesystem check confirming the path no longer exists.
2. **Hard-Purge of Biometric Embeddings**:
   - Embedding vectors in `BiometricEmbedding` and database records in `SubjectImage` and `Subject` are hard-deleted.
3. **Zero-PII Cryptographic Tombstones**:
   - The append-only audit trail records a `SUBJECT_PERMANENTLY_DELETED` event.
   - Plaintext identifiers (`subject_code`, filenames) are never retained in audit records.
   - Non-reversible pseudonymous hashes (`sha256(subject_code)`) and cryptographic tombstone hashes prove compliance without exposing personal data.
4. **Verifiable Deletion Receipts**:
   - Callers receive a cryptographic receipt containing the `subject_hash`, `tombstone_hash`, count of shredded images, count of destroyed vectors, and an explainable decision record.

---

## Explainability & Named Security Engine Rules

In alignment with the FaceTrust Auditor architecture, every deletion operation produces an explainable `Decision` record with named rules:

| Rule | Severity | Fires when |
|---|---|---|
| `DEL-CONFIRMED-SHRED` | info | Explicit cryptographic confirmation (`confirm: true`) is provided |
| `DEL-IMAGES-PURGED` | info | Enrolled biometric image files are forensically overwritten and unlinked |
| `DEL-ZERO-IMAGES` | info | Subject has no stored image files to shred |
| `DEL-EMBEDDINGS-PURGED` | info | Biometric embedding vectors are permanently destroyed |
| `DEL-ZERO-EMBEDDINGS` | info | Subject has no stored embedding vectors |
| `DEL-TOMBSTONE-VERIFIED` | info | Tamper-evident cryptographic tombstone hash is computed |
| `DEL-UNCONFIRMED-REJECTED` | medium | Request lacked explicit confirmation; high-impact destruction denied |
| `DEL-TARGET-NOT-FOUND` | low | Subject identifier was not found in the dataset |
| `DEL-VERIFY-FAILED` | critical | Post-shredding verification check failed (e.g. file still exists) |

---

## Layered Architecture

| Layer | File | Responsibilities |
|---|---|---|
| **Security Engine** | `engine/deletion.py` | NIST SP 800-88 overwriting, path verification, pseudonym generation, tombstone hashing, explainable Decision builder (pure Python / OS utilities, no DB/web dependencies) |
| **Service Layer** | `app/services/deletion_service.py` | Database entity purging, filesystem path resolution, append-only audit recording (`SUBJECT_PERMANENTLY_DELETED`), receipt reconstruction, and tombstone verification |
| **Core Utilities** | `app/core/shredder.py` | Backward-compatible facade delegating to `engine.deletion` |
| **Schemas** | `app/schemas/deletion.py` | Pydantic request validation (`SubjectDeletionRequest`), verifiable receipts (`DeletionReceipt`), history (`DeletionHistoryResponse`), and verification (`DeletionVerifyResponse`) |
| **API Endpoints** | `app/api/v1/deletion.py` | Admin-only deletion endpoint with CSRF and rate limiting, receipt retrieval, history listing, and cryptographic verification |
| **Dataset API** | `app/api/v1/dataset.py` | Backward-compatible `DELETE /dataset/subjects/{id}` and `POST /dataset/subjects/{id}/shred` |
| **Unit & API Tests** | `tests/test_deletion_engine.py`, `tests/test_deletion_api.py`, `tests/test_deletion.py`, `tests/test_shredder.py` | Unit and integration testing |

---

## REST Endpoints (`/api/v1/deletion`)

| Method & Path | Roles | Description |
|---|---|---|
| `POST /api/v1/deletion/subjects/{id}` | Admin only | Permanently shred subject biometrics. Requires active session, CSRF token header (`X-CSRF-Token`), and `confirm: true`. Rate limited to 10/min. |
| `GET /api/v1/deletion/receipts/{tombstone_hash}` | Admin, Analyst, Auditor | Retrieve cryptographic deletion receipt from the immutable audit log. |
| `GET /api/v1/deletion/verify/{tombstone_hash}` | Admin, Analyst, Auditor | Verify that a deletion tombstone is recorded and untampered in the append-only audit trail. |
| `GET /api/v1/deletion/history` | Admin, Analyst, Auditor | List historical deletion events (paginated, zero PII). |

Audit events emitted: `SUBJECT_PERMANENTLY_DELETED`, `DELETION_FAILED`, `ACCESS_DENIED`.

---

## Verification & Test Execution

Run the full FR-6 test suite:
```bash
.venv/bin/pytest tests/test_deletion_engine.py tests/test_deletion_api.py tests/test_deletion.py tests/test_shredder.py -v
```

Run the entire test suite across all FRs:
```bash
.venv/bin/pytest
```
