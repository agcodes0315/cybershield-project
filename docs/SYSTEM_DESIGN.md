# CyberShield: System Design Document

AI-powered Security Operations Center (SOC) platform for critical national infrastructure.

Author: Agrima Saxena
GitHub: [github.com/agcodes0315](https://github.com/agcodes0315)
Repository: [github.com/agcodes0315/cybershield-project](https://github.com/agcodes0315/cybershield-project)

This document explains how CyberShield is put together: how the system is broken into components, how data moves through it, how it scales, and why certain design decisions were made.

Diagrams referenced below live in `docs/diagrams/*.drawio` and can be opened with [diagrams.net](https://app.diagrams.net). Exported PNGs are stored in `docs/images/`.

---

## 1. High Level Design

Diagram: `docs/diagrams/hld.drawio`

### 1.1 Components

| Component | Responsibility |
|---|---|
| React Frontend | SOC dashboard and analyst workspace. Talks to the backend over REST and WebSocket. |
| Express API Gateway | Single entry point for all client traffic. Owns authentication, RBAC, rate limiting, request validation, and routing. |
| FastAPI Detection Engine | Stateless Python service that handles ML based URL scoring, email analysis, reconnaissance, YARA matching, threat feed aggregation, and security analytics. |
| PostgreSQL | System of record for incidents, users, roles, scan history, responses, and audit data. |
| Redis | Low latency caching and, where configured, shared state for coordination across instances. |
| SOAR Orchestrator | Applies risk thresholds and routes findings into automated or human approved response paths. |
| External Threat Feeds | PhishTank, VirusTotal, Have I Been Pwned, Shodan, AbuseIPDB. Accessed only by backend services, never directly by the browser. |

### 1.2 Why this decomposition

Every request from the frontend passes through the gateway first, so authentication and authorization happen at a single, well tested layer. Unauthorized requests are rejected before any downstream compute is spent on them.

The detection engine holds no session state, which means it can scale horizontally without needing sticky sessions.

Redis sits in front of repeat lookups and shared operational state, so the same work isn't recomputed unnecessarily.

Because the gateway and detection engine are separate services, they can be deployed, scaled, and updated independently of each other.

---

## 2. Low Level Design

Diagrams:
`docs/diagrams/threat-pipeline.drawio`
`docs/diagrams/auth-flow.drawio`
`docs/diagrams/response-flow.drawio`
`docs/diagrams/api-flow.drawio`
`docs/diagrams/feature-workflow.drawio`

### 2.1 Threat detection pipeline

1. The client submits a URL or email to `/api/scan/url` or `/api/email/analyze`.
2. The gateway validates the request and applies authentication, RBAC, and rate limits.
3. Redis is checked for an existing result on the same indicator, where caching is configured.
4. On a cache miss, the detection engine extracts the relevant features.
5. URL workflows look at lexical, host, and reputation signals. Email workflows inspect SPF, DKIM, DMARC, and header properties.
6. Findings are enriched with external threat intelligence where available.
7. The detection model produces a risk score.
8. That score is combined with contextual information such as asset criticality.
9. MITRE ATT&CK mapping adds technique and tactic context.
10. The result is written to PostgreSQL.
11. The result is cached in Redis, where configured.
12. New findings are pushed to connected analyst sessions over WebSocket.

### 2.2 Authentication flow

```
Login
  -> Rate Limiter
  -> Lookup User
  -> BCrypt Password Check
  -> JWT Issued
  -> Client Sends Bearer Token
  -> Gateway Verifies Signature and Expiry
  -> RBAC Permission Check
  -> Route Handler
```

The JWT carries the user's role context. Every protected request is checked before it's allowed to reach a downstream service.

### 2.3 Response orchestrator

```
detected -> triaged -> playbook_run -> rejected -> triaged
                              |
                              -> human_approved -> closed
```

Every important transition is written to `audit_log`, so the full incident lifecycle can be reconstructed independently of whatever value is currently stored in `incidents.status`. Higher risk actions are routed through human approval before execution.

### 2.4 API flow

```
React Component
  -> Axios Service Layer
  -> Express Route
  -> Middleware (Helmet, CORS, JWT, RBAC, Rate Limit)
  -> Route Decision: CRUD (PostgreSQL) or Analysis (FastAPI)
  -> Result
  -> Persist / Cache
  -> WebSocket Broadcast + HTTP Response
```

### 2.5 End to end analyst workflow

```
Login -> Dashboard -> URL / Email Analysis -> Threat Intelligence Enrichment
  -> Optional Reconnaissance -> MITRE ATT&CK Mapping -> Risk Scoring
  -> Response Orchestrator
       -> Low Risk: Automated Playbook
       -> Higher Risk: Human Approval
  -> Cyber Resilience Update -> Audit / Reporting
```

WebSocket alerts run alongside this workflow rather than only firing at the final step.

---

## 3. Database Schema

Diagram: `docs/diagrams/database-er.drawio`

| Table | Key Columns | Notes |
|---|---|---|
| `roles` | `id`, `name`, `permission_bitmask` | Analyst, Senior Analyst, SOC Lead |
| `users` | `id`, `email`, `password_hash`, `role_id`, `created_at` | Passwords stored as BCrypt hashes |
| `threat_entries` | `id`, `type`, `target`, `risk_score`, `source`, `scanned_by`, `scanned_at` | One row per analyzed indicator |
| `incidents` | `id`, `source_module`, `risk_score`, `status`, `threat_entry_id`, `assigned_analyst_id`, `created_at`, `updated_at` | Mutable while active |
| `audit_log` | `id`, `incident_id`, `actor`, `action`, `payload_hash`, `prev_hash`, `timestamp` | Append only, hash chained audit trail |
| `responses` | `id`, `incident_id`, `action_type`, `executed_by`, `status`, `executed_at` | Response history |

Relationships:
`roles` to `users` is one to many.
`users` to `threat_entries`, `incidents`, and `responses` is one to many.
`threat_entries` to `incidents` is one to zero or one.
`incidents` to `audit_log` and `responses` is one to many.

### RBAC permission matrix

| Role | View Incidents | Run Automated Playbook | Approve High Risk Action | Manage Users |
|---|:---:|:---:|:---:|:---:|
| Analyst | Yes | No | No | No |
| Senior Analyst | Yes | Low risk only | Yes | No |
| SOC Lead | Yes | Yes | Yes | Yes |

Permissions are checked at the gateway before any protected action reaches a downstream service.

---

## 4. API Flow and Contracts

Diagram: `docs/diagrams/api-flow.drawio`

Representative endpoint groups:

```
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

FastAPI also exposes interactive OpenAPI documentation at `/docs`.

### Rate limiting

| Endpoint Category | Threshold | Rationale |
|---|---:|---|
| `/scan/url` | 30 req/min per analyst | Prevent accidental scan bursts |
| `/scan/email` | 20 req/min per analyst | Control heavier parsing workloads |
| `/orchestrator/execute` | 5 req/min per analyst | Protect high consequence actions |
| `/auth/*` | 10 req/min per IP | Reduce brute force attempts |

---

## 5. Authentication and Authorization

Diagram: `docs/diagrams/auth-flow.drawio`

Key decisions:

Stateless JWT authentication avoids the need for server side session storage.
Gateway level RBAC gives the system a single primary enforcement point.
Passwords are hashed with BCrypt, so plaintext credentials are never persisted.
Role aware middleware checks required permissions before a protected route executes.
Rate limiting around authentication endpoints reduces brute force attempts.

---

## 6. Deployment Architecture

Diagram: `docs/diagrams/deployment.drawio`

| Component | Target |
|---|---|
| Frontend | Azure Static Web Apps |
| API Gateway | Azure Container Apps |
| Detection Engine | Azure Container Apps |
| Persistent Data | PostgreSQL |
| Low Latency State / Cache | Redis |

### Deployment flow

```
GitHub Repository -> CI / Build
  -> Frontend build -> Azure Static Web Apps
  -> Backend images -> Azure Container Apps (Gateway + Detection)
                          -> PostgreSQL
                          -> Redis
```

The browser talks to the frontend and the API gateway over HTTPS and WSS. Backend data services stay behind the application layer and are never exposed directly to the public client.

### Production health checks

```
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```

Deployment verification also covers HTTPS, WSS connectivity, CORS, authentication, database connectivity, detection engine connectivity, and environment variables.

---

## 7. Scaling Considerations

**Stateless services.** The gateway and detection engine don't rely on in memory user sessions, which makes horizontal scaling straightforward.

**Redis.** Reduces repeated computation through cached lookups and can act as a shared coordination layer where needed.

**PostgreSQL.** Remains the system of record. The audit table grows continuously, so a longer term production setup would likely stream historical security events into a dedicated SIEM or analytics store rather than keeping everything in one operational database indefinitely.

**WebSocket fan out.** With a single gateway instance, connected sessions can be tracked in memory. With multiple instances, a shared pub/sub mechanism is needed so alerts generated on one instance reach users connected to another. Redis pub/sub is a natural fit here since Redis is already part of the stack.

**Higher event volume.** At larger scale, the architecture can evolve toward:

```
Redis / Local Coordination
  -> Kafka / Azure Event Hubs
  -> Distributed Detection Workers
  -> SIEM / Analytics Platform
```

AKS or another orchestration platform becomes relevant once the service topology grows beyond what's practical to manage with independent Container Apps.

---

## 8. Security and Trust Boundaries

**Browser to API Gateway.** The browser is treated as untrusted. Authentication, validation, RBAC, and rate limiting all happen before any protected action proceeds.

**API Gateway to Detection Engine.** The detection engine is not meant to become a second public facing authentication surface. The gateway controls who can invoke analysis workflows.

**Detection Engine to External Providers.** Third party threat intelligence responses are treated as external evidence, not absolute truth. Failures, rate limits, and conflicting signals from these providers must never silently bypass application logic.

**Application to Audit Trail.** Security relevant actions generate traceable audit events. Hash chaining gives the system a way to detect unexpected changes to historical records.

---

## 9. Key Design Trade-offs

| Decision | Benefit | Trade-off |
|---|---|---|
| Separate Express and FastAPI services | Clear language and service boundaries | More deployment complexity |
| JWT authentication | Horizontal scalability | Token revocation needs extra design |
| Gateway level RBAC | Centralized authorization | Gateway becomes a critical enforcement point |
| PostgreSQL as system of record | Strong relational consistency | Can become a scaling constraint over time |
| Redis caching | Faster repeated lookups | Cache invalidation has to be handled correctly |
| Human approval for high risk actions | Safer remediation | Slower than a fully autonomous response |
| WebSockets | Immediate analyst updates | Multi instance fan out needs shared pub/sub |
| External threat feeds | Better contextual enrichment | Availability and rate limits are outside the system's control |

---

## 10. Diagram Index

| # | Diagram | File |
|---|---|---|
| 1 | High Level Architecture | `docs/diagrams/hld.drawio` |
| 2 | Threat Detection Pipeline | `docs/diagrams/threat-pipeline.drawio` |
| 3 | Authentication Flow | `docs/diagrams/auth-flow.drawio` |
| 4 | Response Orchestrator | `docs/diagrams/response-flow.drawio` |
| 5 | Deployment Architecture | `docs/diagrams/deployment.drawio` |
| 6 | Database ER Diagram | `docs/diagrams/database-er.drawio` |
| 7 | API Flow | `docs/diagrams/api-flow.drawio` |
| 8 | Feature Workflow | `docs/diagrams/feature-workflow.drawio` |

### Diagram color legend

| Color | Meaning |
|---|---|
| Blue | Frontend / client facing components |
| Green | Gateway / orchestration |
| Orange | Detection / compute |
| Red | Persistent data |
| Yellow | Cache / coordination / decision points |
| Purple | Cloud infrastructure |
| Grey dashed | External systems |

### Exporting PNGs

Open each `.drawio` file in [diagrams.net](https://app.diagrams.net) via File, Open From, Device. Export with File, Export As, PNG, using scale 2x and transparent background off, saving to `docs/images/` with a matching filename. For example, `docs/diagrams/hld.drawio` exports to `docs/images/hld.drawio.png`.

---

## Repository

CyberShield: [github.com/agcodes0315/cybershield-project](https://github.com/agcodes0315/cybershield-project)

Author: Agrima Saxena