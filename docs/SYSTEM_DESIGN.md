# CyberShield — System Design Document

> AI-Powered Security Operations Center (SOC) Platform for Critical National Infrastructure  
> Author: Agrima Saxena · [GitHub](https://github.com/agrima08s010315/cybershield-project)

This document captures the architectural thinking behind CyberShield: how the system is decomposed, how data flows through it, how it scales, and why key design decisions were made.

Diagrams referenced below live in `docs/diagrams/*.drawio` and can be opened with [diagrams.net](https://app.diagrams.net). Exported PNGs are stored in `docs/images/`.

---

## 1. High-Level Design (HLD)

**Diagram:** `docs/diagrams/hld.drawio`

### 1.1 Component Overview

| Component | Responsibility |
|---|---|
| **React Frontend** | SOC dashboard, analyst workspace, and feature modules; communicates with the backend over REST and WebSocket |
| **Express API Gateway** | Single entry point for client traffic; owns authentication, RBAC, rate limiting, request validation, routing, and access control |
| **FastAPI Detection Engine** | Stateless Python service responsible for ML URL scoring, email analysis, reconnaissance, YARA matching, threat-feed aggregation, and security analytics |
| **PostgreSQL** | System of record for incidents, users, roles, scan history, responses, and audit data |
| **Redis** | Supports low-latency state and caching; can also support asynchronous work distribution where configured |
| **SOAR Orchestrator** | Applies risk thresholds and routes findings into automated or human-approved response paths |
| **External Threat Feeds** | Integrations such as PhishTank, VirusTotal, Have I Been Pwned, Shodan, and AbuseIPDB; accessed by backend services, never directly by the browser |

### 1.2 Why This Decomposition

- **Gateway as the sole entry point** — every request from React is authenticated and authorization-checked at one layer. Unauthorized requests are rejected before downstream compute is consumed.
- **Detection engine kept stateless** — FastAPI holds no user-session state, so it can scale horizontally without requiring sticky sessions.
- **Redis as a low-latency support layer** — repeat lookups and shared operational state can avoid unnecessary recomputation where configured.
- **Independent service boundaries** — the gateway and detection engine can be deployed, scaled, and updated separately.

---

## 2. Low-Level Design (LLD)

**Diagrams:**  
`docs/diagrams/threat-pipeline.drawio`  
`docs/diagrams/auth-flow.drawio`  
`docs/diagrams/response-flow.drawio`  
`docs/diagrams/api-flow.drawio`  
`docs/diagrams/feature-workflow.drawio`

### 2.1 Threat Detection Pipeline

1. The client submits a URL or email to `/api/scan/url` or `/api/email/analyze`.
2. The API gateway validates the request and applies authentication, RBAC, and rate limits.
3. Where configured, Redis is checked for an existing result for the same indicator.
4. On a cache miss, the detection engine extracts relevant features.
5. URL workflows may use lexical, host, or reputation signals; email workflows inspect SPF, DKIM, DMARC, and header properties.
6. Findings can be enriched with external threat-intelligence providers.
7. The detection model produces a risk score.
8. Risk is combined with contextual information such as asset criticality.
9. MITRE ATT&CK mapping adds technique and tactic context.
10. The result is persisted to PostgreSQL.
11. Where configured, the result is cached in Redis.
12. New findings can be pushed to connected analyst sessions over WebSocket.

### 2.2 Authentication Flow

```text
Login
  |
  v
Rate Limiter
  |
  v
Lookup User
  |
  v
BCrypt Password Check
  |
  v
JWT Issued
  |
  v
Client Sends Bearer Token
  |
  v
Gateway Verifies Signature + Expiry
  |
  v
RBAC Permission Check
  |
  v
Route Handler
```

The JWT carries the user's role context.

Every protected request is checked before the route is allowed to reach downstream services.

### 2.3 Response Orchestrator

```text
detected
   |
   v
triaged
   |
   v
playbook_run
   |
   +------> rejected
   |            |
   |            v
   |         triaged
   |
   v
human_approved
   |
   v
closed
```

Every important transition is written to `audit_log`.

This allows the complete incident lifecycle to be reconstructed independently of the current value stored in `incidents.status`.

Higher-risk actions are routed through the human approval path before execution.

### 2.4 API Flow

```text
React Component
      |
      v
Axios Service Layer
      |
      v
Express Route
      |
      v
Middleware
Helmet
CORS
JWT
RBAC
Rate Limit
      |
      v
Route Decision
   /       \
  /         \
CRUD       Analysis
 |            |
 v            v
PostgreSQL   FastAPI
  \            /
   \          /
      Result
        |
        v
Persist / Cache
        |
        +------> WebSocket Broadcast
        |
        v
HTTP Response
```

### 2.5 End-to-End Analyst Workflow

```text
Login
  |
  v
Dashboard
  |
  v
URL / Email Analysis
  |
  v
Threat Intelligence Enrichment
  |
  v
Optional Reconnaissance
  |
  v
MITRE ATT&CK Mapping
  |
  v
Risk Scoring
  |
  v
Response Orchestrator
  |
  +------ Low Risk ------> Automated Playbook
  |
  +------ Higher Risk ---> Human Approval
  |
  v
Cyber Resilience Update
  |
  v
Audit / Reporting
```

WebSocket alerts operate alongside the workflow rather than only at its final stage.

---

## 3. Database Schema

**Diagram:** `docs/diagrams/database-er.drawio`

| Table | Key Columns | Notes |
|---|---|---|
| `roles` | `id`, `name`, `permission_bitmask` | Analyst / Senior Analyst / SOC Lead |
| `users` | `id`, `email`, `password_hash`, `role_id`, `created_at` | BCrypt-hashed credentials |
| `threat_entries` | `id`, `type`, `target`, `risk_score`, `source`, `scanned_by`, `scanned_at` | One row per analyzed indicator |
| `incidents` | `id`, `source_module`, `risk_score`, `status`, `threat_entry_id`, `assigned_analyst_id`, `created_at`, `updated_at` | Mutable while active |
| `audit_log` | `id`, `incident_id`, `actor`, `action`, `payload_hash`, `prev_hash`, `timestamp` | Append-oriented, hash-chained audit trail |
| `responses` | `id`, `incident_id`, `action_type`, `executed_by`, `status`, `executed_at` | Response history |

### Relationships

- `roles` 1—N `users`
- `users` 1—N `threat_entries`
- `users` 1—N `incidents`
- `users` 1—N `responses`
- `threat_entries` 1—0..1 `incidents`
- `incidents` 1—N `audit_log`
- `incidents` 1—N `responses`

### RBAC Permission Matrix

| Role | View Incidents | Run Automated Playbook | Approve High-Risk Action | Manage Users |
|---|:---:|:---:|:---:|:---:|
| Analyst | ✅ | ❌ | ❌ | ❌ |
| Senior Analyst | ✅ | ✅ Low Risk | ✅ | ❌ |
| SOC Lead | ✅ | ✅ | ✅ | ✅ |

Permissions are checked at the API gateway before protected actions reach downstream services.

---

## 4. API Flow and Contracts

**Diagram:** `docs/diagrams/api-flow.drawio`

Representative endpoint groups:

```http
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me

POST /api/scan/url
GET  /api/scan/history

POST /api/email/analyze

POST /api/threats/fetch
GET  /api/threats/recent
GET  /api/threats/search

GET  /api/mitre

POST /api/recon/port-scan
POST /api/recon/abuse-check
POST /api/recon/full

GET  /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents/:id/decide
POST /api/resilience/orchestrator/incidents/:id/auto-execute

GET  /api/resilience/audit/trail
GET  /api/resilience/audit/verify
```

FastAPI additionally exposes interactive OpenAPI documentation at:

```text
/docs
```

### Rate Limiting

| Endpoint Category | Threshold | Rationale |
|---|---:|---|
| `/scan/url` | 30 req/min per analyst | Prevent accidental scan bursts |
| `/scan/email` | 20 req/min per analyst | Control heavier parsing workloads |
| `/orchestrator/execute` | 5 req/min per analyst | Protect high-consequence actions |
| `/auth/*` | 10 req/min per IP | Reduce brute-force attempts |

---

## 5. Authentication and Authorization

**Diagram:** `docs/diagrams/auth-flow.drawio`

Key design decisions:

- **Stateless JWT authentication** — avoids requiring server-side session storage.
- **Gateway-level RBAC** — authorization has one primary enforcement point.
- **BCrypt password hashing** — plaintext passwords are not persisted.
- **Role-aware middleware** — protected routes evaluate required permissions before execution.
- **Rate limiting around authentication** — reduces brute-force attempts.

---

## 6. Deployment Architecture

**Diagram:** `docs/diagrams/deployment.drawio`

| Component | Target |
|---|---|
| Frontend | Azure Static Web Apps |
| API Gateway | Azure Container Apps |
| Detection Engine | Azure Container Apps |
| Persistent Data | PostgreSQL |
| Low-Latency State / Cache | Redis |

### Deployment Flow

```text
GitHub Repository
      |
      v
CI / Build
   /      \
  /        \
Frontend   Backend Images
  |             |
  v             v
Azure Static   Azure Container
Web Apps       Apps
                  |
                  v
          API Gateway / Detection
                  |
          +-------+-------+
          |               |
          v               v
     PostgreSQL         Redis
```

The browser communicates with the frontend and API gateway over HTTPS/WSS.

Backend data services remain behind the application layer rather than being directly exposed to the public client.

### Production Health Checks

```http
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```

Deployment verification should also include:

- HTTPS
- WSS WebSocket connectivity
- CORS
- authentication
- database connectivity
- detection-engine connectivity
- environment variables

---

## 7. Scaling Considerations

### Stateless Services

The API gateway and detection engine are designed so application instances do not depend on in-memory user sessions.

That makes horizontal scaling easier.

### Redis

Redis can reduce repeated computation through cached lookups and can provide a shared coordination layer where needed.

### PostgreSQL

PostgreSQL remains the persistent system of record.

The audit table can grow continuously, so long-term production architecture would likely stream historical security events into a dedicated SIEM or analytics store rather than relying on one operational database forever.

### WebSocket Fan-Out

With one gateway instance, connected sessions can be tracked in memory.

With multiple gateway instances, a shared pub/sub mechanism would be required so alerts generated on one instance can reach users connected to another.

Redis pub/sub is a natural extension because Redis is already part of the architecture.

### Higher Event Volume

At higher scale, the architecture can evolve toward:

```text
Redis / Local Coordination
          |
          v
Kafka / Azure Event Hubs
          |
          v
Distributed Detection Workers
          |
          v
SIEM / Analytics Platform
```

AKS or another orchestration platform can become relevant if the service topology grows beyond what is practical to manage with independent Container Apps.

---

## 8. Security and Trust Boundaries

CyberShield separates several trust boundaries explicitly.

### Browser → API Gateway

The browser is treated as untrusted.

Authentication, validation, RBAC, and rate limiting occur before protected actions proceed.

### API Gateway → Detection Engine

The detection engine is not intended to become another public authentication surface.

The gateway controls who may invoke analysis workflows.

### Detection Engine → External Providers

Third-party threat-intelligence responses are treated as external evidence, not absolute truth.

External API failures, rate limits, and conflicting signals must not silently bypass application logic.

### Application → Audit Trail

Security-relevant actions should generate traceable audit events.

Hash chaining provides a mechanism for detecting unexpected historical modification.

---

## 9. Key Design Trade-Offs

| Decision | Benefit | Trade-Off |
|---|---|---|
| Separate Express and FastAPI services | Clear language/service boundaries | More deployment complexity |
| JWT authentication | Horizontal scalability | Token revocation requires additional design |
| Gateway-level RBAC | Centralized authorization | Gateway becomes a critical enforcement point |
| PostgreSQL as system of record | Strong relational consistency | Can become a scaling constraint |
| Redis caching | Faster repeated lookups | Cache invalidation must be handled correctly |
| Human approval for higher-risk actions | Safer remediation | Slower than fully autonomous response |
| WebSockets | Immediate analyst updates | Multi-instance fan-out needs shared pub/sub |
| External threat feeds | Better contextual enrichment | Availability and rate limits are outside system control |

---

## 10. Diagram Index

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

### Diagram Color Legend

| Color | Meaning |
|---|---|
| 🔵 Blue | Frontend / client-facing components |
| 🟢 Green | Gateway / orchestration |
| 🟠 Orange | Detection / compute |
| 🔴 Red | Persistent data |
| 🟡 Yellow | Cache / coordination / decision points |
| 🟣 Purple | Cloud infrastructure |
| ⚪ Grey dashed | External systems |

### Exporting PNGs

Open each `.drawio` file using [diagrams.net](https://app.diagrams.net):

```text
File
  ↓
Open From
  ↓
Device
```

Then export using:

```text
File
  ↓
Export As
  ↓
PNG
```

Recommended settings:

```text
Scale: 2x
Transparent background: Off
Destination: docs/images/
```

Use a matching filename for each exported diagram.

Example:

```text
docs/diagrams/hld.drawio
        ↓
docs/images/hld.drawio.png
```

---

## Repository

**CyberShield:**  
https://github.com/agrima08s010315/cybershield-project

**Author:** Agrima Saxena