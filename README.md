# EcoTrack – Serverless Back‑End (Lambdas & APIs)

**Scope:**
- Onboarding (Auth & Sites)
- Frameworks & Thresholds
- Metrics Ingestion & Alerts
- Reporting

**Stack:** 
- AWS Lambda (Python 3.13)
- API Gateway (HTTP API)
- Aurora PostgreSQL (RDS Data API)
- Secrets Manager
- S3 (reports)
- Amazon SES (e‑mail).

## Table of Contents
1. Architecture
2. Components & Responsibilities
3. Environments & Domains
4. Prerequisites
5. Database Model
6. Shared Environment Variables
7. Per‑Lambda Setup
8. API Reference
9. Security, Auth & CORS
10. Appendix: SQL Snippets

## 1. Architecture
```java
Frontend (Amplify Hosting)
    └── calls API Gateway, HTTP API
                ├─ Lambda: onboarding_api.py     (Journey 1)
                ├─ Lambda: threshold_api.py      (Journey 2)
                ├─ Lambda: metrics_api.py        (Journey 3)
                └─ Lambda: report_api.py         (Journey 4)
Aurora PostgreSQL (RDS, Data API enabled)
AWS Secrets Manager (JWT secret, DB secret)
S3 (report files)
Amazon SES (optional alert emails)
CloudWatch Logs/Alarms
```

## 2. Components & Responsibilities

### 2.1. Onboarding API (Journey 1) — `onboarding_api.py`
- **Auth:** `POST /auth/register` (issuance of JWT).
- **Tenancy:** one user per company (MVP).
- **Sites:** basic site CRUD.
- **JWT** is later used to protect admin/config endpoints.

### 2.2. Configuration & Thresholds (Journey 2) — `threshold_api.py`
- **Framework catalog:** `GET /frameworks`.
- **Assign frameworks to sites:** `POST /site_frameworks`
  - Single upsert or sync by exclusion via assignments array.
- **Thresholds:**
  - `GET /thresholds?site_id=...&framework_code=...`
  - `POST /thresholds` upsert and per‑rule removal via `"remove": true`.
  - **PUE** uses load bands (25/50/75/100). **WUE/CUE** never use bands (must be `NULL`).

### 2.3. Metrics & Alerts (Journey 3) — `metrics_api.py`
- **Ingestion tokens** (one ACTIVE per user):
  - `POST /ingest_tokens` (JWT) → returns plaintext token once.
  - `GET /ingest_tokens` (JWT) → lists masked tokens.
- **Ingest metrics** (token protected):
  - `POST /metrics` with **X-Api-Key** → upsert time‑series & evaluate thresholds across all active frameworks for the site.
  - PUE band chosen by nearest defined band to `it_load_pct`.
  - Opens / escalates / clears alerts in DB.
- **Alerts:** `GET /alerts` (JWT) with filters (status/framework/site).
- **Emails (SES):** send on `OPENED`, `ESCALATED`, `RESOLVED`.

### 2.4. Reports (Journey 4) — `report_api.py`
- **Generate report:** `POST /reports` (JWT) → compute KPIs for a period, upload JSON/CSV to S3, return presigned URL.
- **Inline summary:** `GET /reports/summary` (JWT).
- **Human‑readable title & filename** (e.g.,
`EcoTrack Report — DC West A — GMDC_SG_2024 — 2025-11-01 to 2025-11-10`,
`ecotrack_report_dc-west-a_GMDC_SG_2024_2025-11-01_to_2025-11-10_20251110T134512Z.csv`).
- **Report content** includes site metadata (`name`, `timezone`, `country`).

## 3. Environments & Domains
- **Front-end** (Amplify): https://main.dsjpt9q46sspn.amplifyapp.com/
- **Back-end** (API Gateway)

## 4. Prerequisites
- **AWS account** with permissions to use Lambda, API Gateway (HTTP API), RDS, Secrets Manager, S3, SES.
- **Aurora PostgreSQL** cluster with Data API enabled.
- **DB secret** in Secrets Manager for RDS.
- **JWT secret** in Secrets Manager (value is a strong random string).
- **S3 bucket** for reports (e.g., `ecotrack-reports`).
- **SES identity**: verify the system sender's and recepient's email.

## 5. Database Model
We use UUID PKs everywhere; timestamps are `timestamptz.` Below is a concise view.

### 5.1. Core
- `companies(company_id, name, created_at)`
- `users(user_id, company_id, email, password_hash, is_active, created_at)`
- `sites(site_id, company_id, name, country, timezone, created_at)`

### 5.2. Frameworks & config
- `frameworks(framework_code, name, version, jurisdiction, notes)`
- `site_frameworks(site_id, framework_code, is_active, precedence)`
  - **Unique:** `(site_id, framework_code)`
- `thresholds(threshold_id, company_id, site_id, framework_code, indicator, comparator, threshold_value, severity, load_band, created_at, updated_at)`
  - **PUE:** `load_band ∈ {25,50,75,100}`
  - **WUE/CUE:** `load_band IS NULL`

### 5.3. Ingestion & time‑series
- `ingest_tokens(token_id, company_id, user_id, name, token_hash, active, created_at, last_used_at)`
  - **Unique (partial)**: one ACTIVE per user_id
- `metrics(measurement_id, company_id, site_id, indicator ∈ {PUE,WUE,CUE}, value, it_load_pct, measured_at, created_at, updated_at)`
  - Unique: `(site_id, indicator, measured_at)`

### 5.4. Alerts
- `alerts(alert_id, company_id, site_id, framework_code, indicator, severity ∈ {WARN,CRIT}, comparator, threshold_value, observed_value, status ∈ {OPEN,CLEARED,CLOSED}, raised_at, cleared_at)`

## 6. Shared Environment Variables
### 6.1. All Lambdas (adjust per function):
| Var              | Description                                                   |
| ---------------- | ------------------------------------------------------------- |
| `DB_CLUSTER_ARN` | Aurora (RDS) cluster ARN (Data API enabled).                  |
| `DB_SECRET_ARN`  | Secrets Manager ARN for DB credentials.                       |
| `DB_NAME`        | Database name (e.g., `ecotrack`).                             |
| `JWT_SECRET_ARN` | Secrets Manager ARN for JWT secret (SecretString = HMAC key). |
| `LOG_LEVEL`      | `INFO` (default) or `DEBUG`.                                  |

### 6.2. Reports only
| Var                 | Description              |
| ------------------- | ------------------------ |
| `S3_REPORTS_BUCKET` | Bucket name for reports. |

### 6.3. Metrics (alerts e‑mail) only
| Var                  | Description                                     |
| -------------------- | ----------------------------------------------- |
| `SES_REGION`         | SES region (e.g., `ap-southeast-1`).            |
| `ALERT_EMAIL_SENDER` | Verified sender (e.g., `no-reply@ecotrack.com`). |

## 7. Per‑Lambda Setup
- **Runtime:** Python 3.13
- **Handler:** the module’s `lambda_handler`.

### 7.1. Onboarding (J1) — `onboarding_api.py`
- **Routes (HTTP API):**
  - `POST /auth/register`
  - `POST /auth/login`
  - `GET /sites`
  - `POST /sites`
- **IAM:** `rds-data:*`, `secretsmanager:GetSecretValue`, CloudWatch Logs.

### 7.2. Config & Thresholds (J2) — `threshold_api.py`
- **Routes:**
  - `GET /frameworks`
  - `GET /site_frameworks?site_id=…`
  - `POST /site_frameworks` (single upsert or sync via assignments)
  - `GET /thresholds?site_id=…&framework_code=…`
  - `POST /thresholds` (upsert; per‑rule `"remove": true` support)
  - `GET /alerts` — list alerts.
- **Auth:** JWT required.
- **IAM:** same as J1.

### 7.3. Metrics & Alerts (J3) — `metrics_api.py`
- **Routes:**
  - `POST /ingest_tokens` (JWT) — create one active token per user (plaintext returned once).
  - `GET /ingest_tokens` (JWT) — list tokens.
  - `POST /metrics` (API token) — ingest & evaluate.
- **IAM:** `rds-data:*`, `secretsmanager:GetSecretValue`, CloudWatch Logs, `ses:SendEmail`.

### 7.4. Reports (J4) — `report_api.py`
- **Routes:**
  - `POST /reports` (JWT) — build report, upload to S3, return presigned URL + title/filename.
  - `GET /reports/summary` (JWT) — inline KPIs JSON.
- **IAM:** `rds-data:*`, `secretsmanager:GetSecretValue`, `s3:PutObject`, `s3:GetObject`, `s3:ListBucket`.

## 8. API Reference
- **Base URL (prod)**
- **Auth headers:**
  - JWT: `Authorization: Bearer <token>`
  - Ingest token: `X-Api-Key: <plaintext token>`

### 8.1. Journey 1 — Onboarding
`POST /auth/register`
```bash
curl --location '{baseURL}/auth/register' \
--header 'Content-Type: application/json' \
--data-raw '{
    "company_name": "ABC Company",
    "email": "**********@abc.com",
    "password": "*********"
}'
```

`POST /auth/login`
```bash
curl --location '{baseURL}/auth/login' \
--header 'Content-Type: application/json' \
--data-raw '{
    "email": "**********@abc.com",
    "password": "*********"
}'
```

`GET /sites`
```bash
curl --location '{baseURL}/sites' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}'
```

`POST /sites`
```bash
curl --location '{baseURL}/sites' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}' \
--data '{
    "name": "DC-SG3",
    "country": "SG",
    "timezone": "Asia/Singapore"
}'
```

### 8.2. Journey 2 — Frameworks, Site Assignments, Thresholds
`GET /frameworks`
```bash
curl --location '{baseURL}/frameworks' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}'
```

`GET /site_frameworks?site_id=…`
```bash
curl --location '{baseURL}/site_frameworks?site_id=7a3583e1-803f-471b-a4ff-bd4eeaa62d24' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}'
```

`POST /site_frameworks`
```bash
curl --location '{baseURL}/site_frameworks' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}' \
--data '{
    "site_id": "7a3583e1-803f-471b-a4ff-bd4eeaa62d24",
    "assignments": [
        {
            "framework_code": "GMDC_SG_2024",
            "is_active": true,
            "precedence": 10
        },
        {
            "framework_code": "CORP_DEFAULT",
            "is_active": true,
            "precedence": 20
        },
        {
            "framework_code": "SLA_STRICT",
            "is_active": false,
            "precedence": 30
        }
    ]
}'
```

`GET /thresholds?site_id=…&framework_code=…`
```bash
curl --location '{baseURL}/thresholds?site_id=7a3583e1-803f-471b-a4ff-bd4eeaa62d24&framework_code=GMDC_SG_2024' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}'
```

`POST /thresholds`
```bash
curl --location '{baseURL}/thresholds' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}' \
--data '{
    "framework_code": "GMDC_SG_2024",
    "site_id": "7a3583e1-803f-471b-a4ff-bd4eeaa62d24",
    "rules": [
        {
            "indicator": "PUE",
            "comparator": "<=",
            "value": 1.39,
            "severity": "WARN",
            "load_band": 25,
            "remove": false
        },
        {
            "indicator": "PUE",
            "comparator": "<=",
            "value": 1.46,
            "severity": "CRIT",
            "load_band": 25,
            "remove": false
        },
        {
            "indicator": "WUE",
            "comparator": "<=",
            "value": 2.00,
            "severity": "WARN",
            "remove": false
        },
        {
            "indicator": "WUE",
            "comparator": "<=",
            "value": 2.20,
            "severity": "CRIT",
            "remove": false
        },
        {
            "indicator": "CUE",
            "comparator": "<=",
            "value": 0.564,
            "severity": "WARN",
            "remove": false
        },
        {
            "indicator": "CUE",
            "comparator": "<=",
            "value": 0.592,
            "severity": "CRIT",
            "remove": false
        }
    ]
}'
```

`GET /alerts` — list alerts.
```bash
curl --location '{baseURL}/alerts?site_id=7a3583e1-803f-471b-a4ff-bd4eeaa62d24&framework_code=GMDC_SG_2024&status=OPEN' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}'
```

### 8.3. Journey 3 — Ingest Tokens, Metrics, Alerts
`POST /ingest_tokens`
```bash
curl --location '{baseURL}/ingest_tokens' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}'
```

`GET /ingest_tokens`
```bash
curl --location '{baseURL}/ingest_tokens' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}' \
--data '{
    "name":"Live Testing 2"
}'
```

`POST /metrics`
```bash
curl --location '{baseURL}/metrics' \
--header 'Content-Type: application/json' \
--header 'X-Api-Key: {ingestToken}' \
--data '{
    "site_id": "7a3583e1-803f-471b-a4ff-bd4eeaa62d24",
    "measured_at": "2025-11-09T10:00:00Z",
    "it_load_pct": 25,
    "measurements": [
      { "indicator": "PUE", "value": 1.0 },
      { "indicator": "WUE", "value": 0.5 },
      { "indicator": "CUE", "value": 0.1 }
    ]
  }'
```

### 8.4. Journey 4 — Reports
`POST /reports`
```bash
curl --location '{baseURL}/reports' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}' \
--data '{
    "site_id": "7a3583e1-803f-471b-a4ff-bd4eeaa62d24",
    "framework_code": "GMDC_SG_2024",
    "from": "2025-11-01T00:00:00Z",
    "to": "2025-11-30T00:00:00Z",
    "format": "json"
}'
```

`GET /reports/summary`
```bash
curl --location '{baseURL}/reports/summary?site_id=7a3583e1-803f-471b-a4ff-bd4eeaa62d24&framework_code=GMDC_SG_2024&from=2025-11-01T00%3A00%3A00Z&to=2025-11-30T00%3A00%3A00Z' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {bearerToken}'
```

## 9. Security, Auth & CORS
- **JWT (HMAC‑SHA256):** signed with secret from `JWT_SECRET_ARN`.
- **Ingest token:** random plaintext (shown once), stored as `SHA‑256` hash, one ACTIVE per user.
- CORS (Option A, different subdomains):
  - API should allow https://main.dsjpt9q46sspn.amplifyapp.com/ (except `POST /metrics`)
  - Headers: `Content-Type`, `Authorization`, `X-Api-Key` (only for `POST /metrics`)
  - Methods: `GET`, `POST`, `OPTIONS`

## 10. Appendix: SQL Snippets

### 10.1. Frameworks – add GDCR (idempotent)
```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_frameworks_code ON frameworks(framework_code);
INSERT INTO frameworks (framework_code, name, notes, jurisdiction, version)
VALUES ('GDCR_SG_2034', 'Green Data Centre Roadmap', 'Singapore IMDA/EMA', 'SG', '2034')
ON CONFLICT (framework_code) DO NOTHING;
```

### 10.2. Enforce PUE vs WUE/CUE band rule
```sql
ALTER TABLE thresholds
  ADD CONSTRAINT IF NOT EXISTS chk_indicator_load_band
  CHECK (
    (indicator = 'PUE' AND load_band IN (25,50,75,100))
    OR
    (indicator IN ('WUE','CUE') AND load_band IS NULL)
  );
```

### 10.3. Ingest tokens – one active per user
```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_ingest_active_per_user
  ON ingest_tokens (user_id) WHERE active = TRUE;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ingest_token_hash
  ON ingest_tokens (token_hash);
```

### 10.4. Metrics unique key
```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_metrics_site_indicator_ts
  ON metrics(site_id, indicator, measured_at);
```