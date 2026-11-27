# FaceTrust Auditor — Backend API & Security Architecture

## Overview
FaceTrust Auditor is a local facial recognition security lab built with FastAPI, SQLAlchemy, and a pure-Python security engine (`engine/`).

## API Endpoints (`/api/v1`)
- **Health:** `GET /health`
- **Auth & Users:** `POST /auth/login`, `POST /auth/logout`, `GET /users/me`, `POST /users` (admin)
- **Dataset & Consent (FR-1, FR-6):**
  - `POST /dataset/subjects`, `GET /dataset/subjects`, `GET /dataset/subjects/{id}`
  - `POST /dataset/subjects/{id}/images`, `GET /dataset/subjects/{id}/images/{img_id}/download`
  - `POST /dataset/subjects/{id}/withdraw`, `DELETE /dataset/subjects/{id}` (secure shredder + DB purge)
- **Evaluations & Thresholds (FR-3, FR-4, FR-5):**
  - `POST /evaluations/threshold`, `POST /evaluations/bias-audit`, `POST /evaluations/liveness`
  - `GET /evaluations`, `GET /evaluations/{run_id}`, `GET /evaluations/{run_id}/export?format=json|csv`
- **Policy & Reports (FR-6):**
  - `GET /policy`, `PATCH /policy` (admin), `GET /policy/history` (admin/auditor)
  - `GET /reports/json`, `GET /reports/csv` (admin/auditor)
- **Audit:** `GET /audit/logs`, `GET /audit/verify`

## Security Guarantees
- **Encryption at Rest:** Biometric images and embeddings are encrypted using AES-256-GCM before touching disk/DB.
- **Tamper-Evident Audit Log:** Every sensitive action appends a SHA-256 hash-chained `AuditLog` entry.
- **Sanitized Exports:** JSON/CSV reports contain zero PII and include a deterministic `report_integrity_hash`.
- **RBAC & CSRF:** Role-based access control (`admin`, `auditor`, `analyst`) and CSRF token validation on state-changing requests.
