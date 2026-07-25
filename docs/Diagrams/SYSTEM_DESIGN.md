# CyberShield — System Design Document

> AI-Powered Security Operations Center (SOC) Platform for Critical National Infrastructure
> Author: Agrima Saxena · [GitHub](https://github.com/agrima150103/cybershield-project)

This document captures the architectural thinking behind CyberShield: how the system is
decomposed, how data flows through it, how it scales, and why key design decisions were made.
Diagrams referenced below live in `docs/diagrams/*.drawio` (open at [app.diagrams.net](https://app.diagrams.net))
with exported PNGs in `docs/images/`.

---

## 1. High-Level Design (HLD)

**Diagram:** `docs/diagrams/hld.drawio`

### 1.1 Component overview

| Component | Responsibility |
|---|---|
| **React Frontend** | SOC dashboard, analyst workspace, all 12 feature modules; talks to the backend exclusively over REST (Axios) and WebSocket |
| **Express API Gateway** | Single entry point for all client traffic. Owns authentication, RBAC, rate limiting, request validation, and routing to the detection engine and data layer |
| **FastAPI Detection Engine** | Stateless Python service that performs the actual analysis: ML URL scoring, email header analysis, reconnaissance, YARA matching, and threat-feed aggregation |
| **PostgreSQL** | System of record — incidents, users, roles, audit trail |
| **Redis** | Two roles: (a) response cache for repeat URL/domain lookups, (b) work queue absorbing longer-running scans so the gateway isn't blocked synchronously |
| **SOAR Orchestrator** | Consumes queued findings, applies the risk-threshold decision, and drives either the automated playbook or the human-approval path |
| **External Threat Feeds** | PhishTank, VirusTotal, Have I Been Pwned, Shodan, AbuseIPDB — called from the detection engine, never directly from the client |

### 1.2 Why this decomposition

- **Gateway as sole entry point** — every request (React → Express) is authenticated and RBAC-checked once, at one layer, so the FastAPI engine and database never need to duplicate auth logic. An unauthorized request is rejected before it consumes detection-engine compute.
- **Redis as a shock absorber** — the gateway must stay responsive under bursty analyst activity (e.g. a bulk IOC search). Long-running work (YARA scan, recon) is queued rather than held open synchronously.
- **Detection engine kept stateless** — FastAPI holds no session or user state, so it can scale horizontally behind Container Apps autoscaling without sticky sessions.

---

## 2. Low-Level Design (LLD)

**Diagrams:** `docs/diagrams/threat-pipeline.drawio`, `auth-flow.drawio`, `response-flow.drawio`, `api-flow.drawio`, `feature-workflow.drawio`

### 2.1 Threat Detection Pipeline

1. Client submits a URL or email to `/api/scan/url` or `/api/email/analyze`.
2. Gateway checks Redis for a cached verdict on that exact indicator (cache hit → skip straight to response, no detection-engine call).
3. On a miss, the detection engine extracts features (lexical/domain-age for URLs; SPF/DKIM/DMARC for email headers).
4. Extracted features are enriched against the external threat-intel APIs.
5. The Random Forest + Gradient Boosting model produces a risk score.
6. The score is weighted by asset criticality (context-aware prioritization).
7. MITRE ATT&CK keyword mapping tags the finding with technique/tactic.
8. Result is persisted to PostgreSQL and write-through cached in Redis.
9. Result is pushed to all connected analysts over WebSocket and rendered on the dashboard.

### 2.2 Authentication Flow

Login → rate limiter (10 req/min/IP) → lookup `users` row by email → BCrypt compare →
on success, sign a JWT carrying the user's `role_id` → client stores the token → every
subsequent request carries `Authorization: Bearer <JWT>` → gateway middleware verifies
signature + expiry, then checks the role's `permission_bitmask` before the request is
allowed to reach a route handler.

### 2.3 Response Orchestrator (state machine)

```
detected → triaged → playbook_run → human_approved → closed
              │                            │
              └──────── rejected ──────────┘
                (returns to triaged with a note)
```

Every transition is written as its own row in `audit_log` — the incident's full lifecycle
is reconstructable from the log alone, independent of the current `incidents.status` value.
The orchestrator **never** auto-executes anything above the configured risk threshold; that
path always routes through the human approval gate first.

### 2.4 API Flow

React component → Axios service layer → Express route → middleware chain (Helmet → CORS →
JWT auth → RBAC → rate limiter) → branch: does this route need analysis (→ FastAPI) or is
it a direct CRUD read/write (→ PostgreSQL)? → result persisted / cached → response assembled
→ if the result represents a new incident or alert, a WebSocket broadcast fires in parallel
→ response returned to the client.

### 2.5 Feature Workflow (end-to-end analyst journey)

Login → Dashboard → URL/Email Scan → Threat Intelligence enrichment (+ optional
Reconnaissance) → MITRE Mapping → Risk Scoring → Response Orchestrator (playbook or
approval) → Cyber Resilience Engine update → PDF Report. WebSocket alerts run alongside
this entire chain, not just at the end.

---

## 3. Database Schema

**Diagram:** `docs/diagrams/database-er.drawio`

| Table | Key columns | Notes |
|---|---|---|
| `roles` | `id` PK, `name`, `permission_bitmask` | Analyst / Senior Analyst / SOC Lead |
| `users` | `id` PK, `email`, `password_hash`, `role_id` FK → roles, `created_at` | BCrypt-hashed credentials |
| `threat_entries` | `id` PK, `type` (url/email), `target`, `risk_score`, `source`, `scanned_by` FK → users, `scanned_at` | Raw scan results, one row per analyzed indicator |
| `incidents` | `id` PK, `source_module`, `risk_score`, `status`, `threat_entry_id` FK → threat_entries (nullable), `assigned_analyst_id` FK → users, `created_at`, `updated_at` | Mutable while `status != closed` |
| `audit_log` | `id` PK, `incident_id` FK → incidents, `actor`, `action`, `payload_hash`, `prev_hash`, `timestamp` | **Append-only** — no `UPDATE`/`DELETE` grants at the DB role level. `prev_hash` chains each row to the previous entry, so tampering breaks the chain and is detectable on verification |
| `responses` | `id` PK, `incident_id` FK → incidents, `action_type`, `executed_by` FK → users, `status`, `executed_at` | One row per orchestrator-executed or analyst-approved action |

### Relationships
- `roles` 1—N `users`
- `users` 1—N `threat_entries` (scans performed)
- `users` 1—N `incidents` (assigned analyst)
- `users` 1—N `responses` (executed by)
- `threat_entries` 1—0..1 `incidents` (a scan escalates to an incident)
- `incidents` 1—N `audit_log`
- `incidents` 1—N `responses`

### RBAC permission matrix

| Role | View incidents | Run automated playbook | Approve high-risk action | Manage users |
|---|:---:|:---:|:---:|:---:|
| Analyst | ✅ | ❌ | ❌ | ❌ |
| Senior Analyst | ✅ | ✅ (low-risk only) | ✅ | ❌ |
| SOC Lead | ✅ | ✅ | ✅ | ✅ |

Permissions are stored as a bitmask on `roles` and checked at the API gateway layer —
before a request ever reaches the FastAPI detection engine.

---

## 4. API Flow & Contracts

**Diagram:** `docs/diagrams/api-flow.drawio`

All client traffic passes through the Express gateway. Representative endpoint groups:

```
POST /api/auth/register            POST /api/scan/url
POST /api/auth/login               GET  /api/scan/history
GET  /api/auth/me                  POST /api/email/analyze

POST /api/threats/fetch            GET  /api/mitre
GET  /api/threats/recent           POST /api/recon/port-scan
GET  /api/threats/search           POST /api/recon/abuse-check
                                    POST /api/recon/full

GET  /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents/:id/decide
POST /api/resilience/orchestrator/incidents/:id/auto-execute
GET  /api/resilience/audit/trail
GET  /api/resilience/audit/verify
```

FastAPI additionally exposes interactive OpenAPI docs at `/docs` covering URL Analysis,
Email Analysis, Reconnaissance, Vulnerability Prioritization, Response Orchestration,
Audit, and Cyber Resilience.

### Rate limiting

| Endpoint category | Threshold | Rationale |
|---|---|---|
| `/scan/url` | 30 req/min/analyst | Prevents accidental scan storms against one domain |
| `/scan/email` | 20 req/min/analyst | Email parsing is more compute-heavy |
| `/orchestrator/execute` | 5 req/min/analyst | Highest-consequence action in the system |
| `/auth/*` | 10 req/min/IP | Standard brute-force mitigation |

---

## 5. Authentication & Authorization Flow

**Diagram:** `docs/diagrams/auth-flow.drawio` — see §2.2 above for the narrative walkthrough.

Design decisions worth calling out explicitly:
- **Stateless JWTs**, not server-side sessions — keeps the gateway horizontally scalable
  without a shared session store.
- **RBAC enforced at the gateway**, not in each downstream service — one choke point,
  one audit surface.
- **Password hashing via BCrypt** with per-user salt; plaintext credentials never touch
  the database or logs.

---

## 6. Deployment Architecture

**Diagram:** `docs/diagrams/deployment.drawio`

| Component | Target |
|---|---|
| Frontend | Azure Static Web Apps — build `npm run build`, serve `dist/` |
| API Gateway | Azure Container App (independently scalable) |
| Detection Engine | Azure Container App — separate service from the gateway |
| Data layer | Managed PostgreSQL + Azure Cache for Redis |

**Flow:** GitHub push → CI build → Static Web Apps gets the frontend bundle; Container
Apps get the gateway and detection-engine images. The browser talks to Static Web Apps
for the SPA shell, then to the gateway Container App over HTTPS/WSS for everything else.
The gateway is the only component with a network path to PostgreSQL, Redis, and (via the
detection engine) the external threat feeds — neither data store nor the detection engine
is directly reachable from the public internet.

**Production health checks:**
```
GET /health/live        GET /api/auth/me
GET /health              GET /api/threats/recent   GET /api/mitre
```
Plus verification of HTTPS, WSS connectivity, CORS configuration, DB/Redis connectivity,
and environment variables on every deploy.

---

## 7. Scaling Considerations

- **Stateless services first.** Both the Express gateway and the FastAPI detection engine
  hold no in-memory session state, so Azure Container Apps can scale either service
  horizontally on its own trigger (HTTP concurrency for the gateway; queue depth for the
  detection engine) without sticky sessions.
- **Redis absorbs burst load.** Cache hits short-circuit repeat lookups; the queue role
  lets the gateway return quickly while longer scans (YARA, recon) process asynchronously.
- **Database as the scaling constraint.** PostgreSQL is currently a single managed
  instance. The `audit_log` table is append-only and grows unbounded — the roadmap's
  SIEM Integration item (streaming `audit_log` out to Syslog/CEF) exists partly to keep
  this table from becoming the long-term system of record for every raw event.
- **WebSocket fan-out** is currently per-gateway-instance in-memory. Scaling the gateway
  horizontally beyond one instance requires a shared pub/sub layer (Redis pub/sub is the
  natural next step, since Redis is already in the stack) so an alert generated on one
  instance reaches analysts connected to another.
- **Known ceiling:** the roadmap explicitly calls out migrating Redis-as-queue to
  Kafka/Azure Event Hubs once incident volume exceeds what single-instance buffering can
  handle, and moving the detection engine + gateway to AKS with autoscaling keyed on
  Redis queue depth once Container Apps' scaling model is outgrown.

---

## 8. Diagram Index

| # | Diagram | File |
|---|---|---|
| 1 | High-Level Architecture | `docs/diagrams/hld.drawio` |
| 2 | Threat Detection Pipeline | `docs/diagrams/threat-pipeline.drawio` |
| 3 | Authentication Flow | `docs/diagrams/auth-flow.drawio` |
| 4 | Response Orchestrator | `docs/diagrams/response-flow.drawio` |
| 5 | Deployment Architecture | `docs/diagrams/deployment.drawio` |
| 6 | Database ER Diagram | `docs/diagrams/database-er.drawio` |
| 7 | API Flow | `docs/diagrams/api-flow.drawio` |
| 8 | Feature Workflow | `docs/diagrams/feature-workflow.drawio` |

**Color legend used across all diagrams:**

| Color | Meaning |
|---|---|
| 🔵 Blue | Frontend / client-facing (React) |
| 🟢 Green | Gateway / orchestration layer (Express) |
| 🟠 Orange | Compute / detection engine (FastAPI, ML) |
| 🔴 Red | Persistent data of record (PostgreSQL, audit log) |
| 🟡 Yellow | Cache/queue (Redis) or decision points |
| 🟣 Purple | Cloud/Azure infrastructure |
| ⚪ Grey dashed | External third-party systems (threat feed APIs) |

### How to export PNGs
Open each `.drawio` file at [app.diagrams.net](https://app.diagrams.net) (File → Open From →
Device), then **File → Export as → PNG**, 2x scale, transparent background off, and save
into `docs/images/` using the matching filename (e.g. `hld.png`).
