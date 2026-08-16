<div align="center">

# 🛡️ CyberShield

### AI-Assisted Security Operations Center Platform for Critical Infrastructure

A full-stack cybersecurity platform combining **threat intelligence, attack-graph analysis, phishing detection, vulnerability prioritization, incident response, MITRE ATT&CK mapping and analyst-governed remediation**.

<br>

![React](https://img.shields.io/badge/React-20232A?style=flat&logo=react&logoColor=61DAFB)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat&logo=redis&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-140%20Passing-2EA44F?style=flat&logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

<br>

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Open%20CyberShield-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
[![Repository](https://img.shields.io/badge/GitHub-Source%20Code-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/agrima08s010315/cybershield-project)

</div>

## Overview

CyberShield is a production-inspired Security Operations Center platform built around a simple problem: security analysts often have to move between disconnected tools for threat intelligence, phishing analysis, vulnerability assessment, malware inspection and incident response.

CyberShield brings those workflows into one system.

The platform combines a **React frontend, Express API gateway, FastAPI detection engine, PostgreSQL, Redis and Azure deployment** with security-focused features such as attack-path analysis, MITRE ATT&CK mapping, YARA scanning, threat-feed correlation, response orchestration and auditable analyst actions.

The project is designed primarily as an engineering and defensive-security portfolio system. It focuses not only on features, but also on service boundaries, algorithms, testing, security controls and reproducible performance work.

## Live Deployment

| Service | Deployment |
|---|---|
| **Frontend** | [Azure Static Web App](https://mango-pebble-099d8de00.7.azurestaticapps.net/) |
| **API Gateway** | [Azure Container App](https://cybershield-api-gateway.niceforest-87cbfff3.centralindia.azurecontainerapps.io) |

## Project Highlights

- Full-stack SOC platform built with **React, Express.js, FastAPI, PostgreSQL and Redis**
- Graph-based attack-path analysis using **BFS, DFS and Dijkstra's algorithm**
- Reworked critical-asset discovery with a measured **~99.97% reduction in median benchmark latency**
- Benchmark performed on a **2,500-node / 10,000-edge synthetic attack graph**
- **140 automated unit and integration tests**
- ML-assisted phishing and URL analysis
- YARA-based malware inspection
- MITRE ATT&CK technique and tactic mapping
- Real-time analyst updates through WebSockets
- Human-governed response orchestration
- Hash-chained audit logging
- Azure cloud deployment

### Current Service Status

| Component | Status |
|---|---|
| Frontend | ✅ Live |
| API Gateway | ✅ Live |
| Detection Engine | ✅ Running |
| PostgreSQL | ✅ Connected |
| WebSockets | ✅ Enabled |

## Problem

Security teams often work with separate tools for:

- URL and phishing analysis
- email investigation
- vulnerability assessment
- threat intelligence
- malware detection
- attack-path reasoning
- incident response
- security reporting

This fragmentation creates duplicated work and makes it harder to understand how individual findings relate to a wider attack path.

CyberShield approaches the problem as one connected workflow:

```text
Detection
   |
   v
Enrichment
   |
   v
Risk Analysis
   |
   v
Attack-Path Context
   |
   v
MITRE ATT&CK Mapping
   |
   v
Analyst Decision
   |
   v
Response / Audit
```

## Key Capabilities

### Security Operations

- SOC command-center dashboard
- real-time security monitoring
- threat-feed views
- analyst workspace
- incident lifecycle tracking

### Threat Intelligence

- ML-assisted URL scanner
- email-header analysis
- SPF, DKIM and DMARC checks
- IP and domain reputation analysis
- reconnaissance workflows
- external threat-feed connectors

### Attack Graph Intelligence

- directed infrastructure graphs
- BFS minimum-hop paths
- Dijkstra lowest-cost paths
- DFS blast-radius analysis
- critical-asset discovery
- containment simulation
- remediation prioritization

### Vulnerability Management

- context-aware risk scoring
- vulnerability prioritization
- patch prioritization
- asset criticality ranking

### Malware Analysis

- YARA rule engine
- signature-based analysis
- IOC detection

### Incident Response

- analyst approval workflows
- response orchestrator
- automated low-risk playbooks
- action history
- audit trail
- remediation tracking

### Cyber Resilience

- security-event correlation
- organizational risk assessment
- attack-path context
- resilience analytics

## System Architecture

CyberShield follows a multi-service architecture.

The React frontend communicates with the Express API gateway, which is responsible for authentication, authorization, API routing and access control.

The FastAPI service handles detection and analysis workloads. PostgreSQL stores application data while Redis supports low-latency state and caching where configured.

<p align="center">
  <img src="./docs/images/hld.drawio.png"
       alt="CyberShield High Level Design"
       width="92%">
</p>

<p align="center">
  <sub>High-level system design and major service boundaries.</sub>
</p>

### API Flow

Requests from the frontend pass through the API gateway before reaching backend analysis services.

<p align="center">
  <img src="./docs/images/api-flow.drawio.png"
       alt="CyberShield API Flow"
       width="92%">
</p>

### Authentication Flow

Authentication and authorization are enforced before protected actions reach the detection layer.

<p align="center">
  <img src="./docs/images/auth-flow.drawio.png"
       alt="CyberShield Authentication Flow"
       width="90%">
</p>

### Deployment Architecture

The frontend and backend components are deployed independently.

<p align="center">
  <img src="./docs/images/deployment_architecture.drawio.png"
       alt="CyberShield Deployment Architecture"
       width="92%">
</p>

> If your deployment PNG has a slightly different filename, replace `deployment_architecture.drawio.png` with the exact filename present inside `docs/images/`.

## Low-Level Design

### Entity Relationship Model

PostgreSQL stores users, roles, incidents, findings, operational state and audit records.

<p align="center">
  <img src="./docs/images/ER_Diagram_Clean.drawio.png"
       alt="CyberShield Entity Relationship Diagram"
       width="90%">
</p>

### Feature Workflow

The feature workflow connects detection, enrichment, analysis and response.

<p align="center">
  <img src="./docs/images/feature-workflow.drawio.png"
       alt="CyberShield Feature Workflow"
       width="92%">
</p>

### Threat Processing Pipeline

Threat data passes through multiple analysis and enrichment stages before it reaches analyst-facing workflows.

<p align="center">
  <img src="./docs/images/threat-pipeline.drawio.png"
       alt="CyberShield Threat Processing Pipeline"
       width="92%">
</p>

### Response Flow

Higher-risk actions are separated from lower-risk automation through analyst approval.

<p align="center">
  <img src="./docs/images/response-flow.drawio.png"
       alt="CyberShield Response Flow"
       width="92%">
</p>

Editable Draw.io source files are available in [`docs/diagrams/`](./docs/diagrams/).

Additional design documentation is available in [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md).

## Incident and Audit Design

### Incident table

Important fields include:

```text
id
source_module
risk_score
status
created_at
updated_at
```

### Audit log

The audit trail stores fields such as:

```text
id
incident_id
actor
action
payload_hash
prev_hash
timestamp
```

Audit records are chained using the previous record hash.

If a historical row is modified outside the expected workflow, chain verification can detect the inconsistency.

### Incident Lifecycle

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
   |
   v
human_approved
   |
   v
closed
```

Each important transition is recorded in the audit trail rather than relying only on the current incident status.

## RBAC

| Role | View Incidents | Run Playbook | Approve High-Risk Action | Manage Users |
|---|:---:|:---:|:---:|:---:|
| Analyst | ✅ | ❌ | ❌ | ❌ |
| Senior Analyst | ✅ | ✅ Low Risk | ✅ | ❌ |
| SOC Lead | ✅ | ✅ | ✅ | ✅ |

Authorization checks occur at the API gateway before protected actions reach downstream services.

## Rate Limiting

| Endpoint | Limit | Purpose |
|---|---:|---|
| `/scan/url` | 30 req/min per analyst | Prevent accidental scan bursts |
| `/scan/email` | 20 req/min per analyst | Control heavier parsing workload |
| `/orchestrator/execute` | 5 req/min per analyst | Protect high-impact actions |
| `/auth/*` | 10 req/min per IP | Reduce brute-force attempts |

## Algorithm Engineering

CyberShield represents infrastructure assets and trust relationships as a directed weighted graph.

The attack-graph implementation uses:

- **BFS** for minimum-hop attack paths
- **Dijkstra's algorithm** for weighted attack paths
- **DFS** for blast-radius and compromise reachability
- **hash maps and sets** for asset and membership lookup
- **priority queues** for remediation ranking
- **adjacency lists** for graph storage

### Critical-Asset Discovery

The earlier implementation ran Dijkstra independently for each critical asset.

For `K` critical assets, the approximate cost was:

```text
O(K × (V + E) log V)
```

The implementation was then changed to use a single-source shortest-path traversal together with hash-set membership checks.

The resulting approximation is:

```text
O((V + E) log V + K)
```

## Performance Benchmark

The before and after implementations were benchmarked against the same deterministic synthetic graph generator.

| Metric | Before | After |
|---|---:|---:|
| Graph nodes | 2,500 | 2,500 |
| Graph edges | 10,000 | 10,000 |
| Critical assets | 125 | 125 |
| Mean latency | 2434.16 ms | 0.84 ms |
| Median latency | 2461.10 ms | 0.83 ms |
| P95 latency | 2582.02 ms | 0.90 ms |

**Median critical-asset discovery latency decreased from approximately 2.46 seconds to 0.83 milliseconds in the recorded benchmark session.**

That corresponds to an approximate **99.97% reduction in median latency** for the benchmarked operation.

Absolute runtimes vary between machines and benchmark sessions, so the repository includes the evaluation artifacts needed to inspect the comparison.

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

The optimized implementation was also run against the automated test suite:

```text
140 passed
```

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Axios, Recharts, Lucide React, CSS3 |
| API Gateway | Node.js, Express.js, JWT, Helmet, CORS, Rate Limiting |
| Detection Engine | Python, FastAPI, scikit-learn, YARA, Nmap, WHOIS |
| Database | PostgreSQL |
| Low-Latency State / Caching | Redis |
| Realtime | WebSockets |
| Cloud | Microsoft Azure |
| Deployment | Static Web Apps, Container Apps, Docker |
| Testing | pytest, unit and integration testing |

## Implemented Modules

| Module | Purpose |
|---|---|
| SOC Dashboard | Central security operations view |
| URL Scanner | ML-assisted suspicious URL analysis |
| Email Analyzer | Email-header and spoofing analysis |
| Reconnaissance | Domain and network intelligence |
| MITRE ATT&CK Mapping | Technique and tactic mapping |
| Attack Graph | Attack paths and blast-radius analysis |
| Breach Checker | Credential exposure checks |
| Pen Testing | Controlled vulnerability assessment |
| YARA Scanner | Malware rule matching |
| GoPhish Simulator | Security awareness workflows |
| Cyber Resilience | Risk and resilience analysis |
| Response Orchestrator | Response workflow coordination |
| SOC Community | Threat intelligence collaboration |
| Settings | Workspace configuration |

## AI and Analytics

CyberShield uses ML and analytics for selected workflows rather than treating every capability as an AI problem.

Current areas include:

- phishing URL analysis
- behavioural risk signals
- vulnerability prioritization
- event correlation
- incident recommendation support
- email spoofing analysis
- organizational resilience scoring

## Security Controls

The platform includes:

- JWT authentication
- BCrypt password hashing
- role-based access control
- input validation
- rate limiting
- parameterized database queries
- human approval for higher-risk response actions
- hash-chained audit records
- secure Azure deployment
- protected API routes

## Project Structure

```text
CyberShield/
|
├── client/
│   ├── src/
│   │   ├── components/
│   │   ├── context/
│   │   ├── hooks/
│   │   ├── pages/
│   │   ├── services/
│   │   └── App.jsx
│   └── package.json
|
├── api-gateway/
│   ├── config/
│   ├── middleware/
│   ├── routes/
│   ├── utils/
│   ├── app.js
│   ├── server.js
│   └── package.json
|
├── detection-engine/
│   ├── app/
│   │   ├── attack_graph/
│   │   │   ├── graph.py
│   │   │   ├── pathfinder.py
│   │   │   ├── blast_radius.py
│   │   │   └── remediation.py
│   │   └── ...
│   ├── models/
│   ├── rules/
│   └── requirements.txt
|
├── docs/
│   ├── diagrams/
│   │   ├── api-flow.drawio
│   │   ├── auth-flow.drawio
│   │   ├── hld.drawio
│   │   └── ...
│   |
│   ├── images/
│   │   ├── api-flow.drawio.png
│   │   ├── auth-flow.drawio.png
│   │   ├── hld.drawio.png
│   │   ├── feature-workflow.drawio.png
│   │   ├── response-flow.drawio.png
│   │   ├── threat-pipeline.drawio.png
│   │   └── ...
│   |
│   └── SYSTEM_DESIGN.md
|
├── tests/
│   ├── unit/
│   ├── integration/
│   └── scenarios/
|
├── evaluation/
│   ├── baselines/
│   ├── benchmark_graph_algorithms.py
│   ├── graph_algorithm_benchmark_before.csv
│   ├── graph_algorithm_benchmark_after.csv
│   └── graph_algorithm_verified_run.txt
|
├── docker-compose.yml
└── README.md
```

## API Endpoints

<details>
<summary><b>Authentication</b></summary>

```http
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me
```

</details>

<details>
<summary><b>URL Analysis</b></summary>

```http
POST /api/scan/url
GET  /api/scan/history
```

</details>

<details>
<summary><b>Email Analysis</b></summary>

```http
POST /api/email/analyze
```

</details>

<details>
<summary><b>Threat Intelligence</b></summary>

```http
POST /api/threats/fetch
GET  /api/threats/recent
GET  /api/threats/search
```

</details>

<details>
<summary><b>MITRE ATT&CK</b></summary>

```http
GET /api/mitre
```

</details>

<details>
<summary><b>Reconnaissance</b></summary>

```http
POST /api/recon/port-scan
POST /api/recon/abuse-check
POST /api/recon/full
```

</details>

<details>
<summary><b>Cyber Resilience</b></summary>

```http
GET  /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents/:id/decide
POST /api/resilience/orchestrator/incidents/:id/auto-execute

GET  /api/resilience/audit/trail
GET  /api/resilience/audit/verify
```

</details>

FastAPI also exposes interactive API documentation at:

```text
/docs
```

## Local Setup

### Prerequisites

- Node.js 20+
- Python 3.11+
- PostgreSQL
- Redis
- Git

### Clone

```bash
git clone https://github.com/agrima08s010315/cybershield-project.git
cd cybershield-project
```

### API Gateway

```bash
cd api-gateway
npm install
npm run dev
```

### Detection Engine

```bash
cd detection-engine

python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS / Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run FastAPI:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```bash
cd client
npm install
npm run dev
```

Then open:

```text
http://127.0.0.1:5173
```

## Environment Variables

### `api-gateway/.env`

```env
NODE_ENV=development
PORT=5000

DATABASE_URL=postgresql://postgres:password@localhost:5432/cybershield

JWT_SECRET=replace_with_a_secure_secret

DETECTION_ENGINE_URL=http://127.0.0.1:8000

CORS_ORIGINS=http://localhost:5173

REDIS_URL=
```

### `client/.env`

```env
VITE_API_BASE_URL=http://127.0.0.1:5000/api
VITE_WS_URL=ws://127.0.0.1:5000/ws
```

Do not commit production secrets or real provider API keys.

## Azure Deployment

| Component | Azure Service |
|---|---|
| Frontend | Azure Static Web Apps |
| API Gateway | Azure Container Apps |
| Detection Engine | Azure Container Apps |
| Containerization | Docker |

Useful production checks include:

```http
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```

Deployment verification should also cover:

- HTTPS
- WSS WebSocket connectivity
- CORS
- JWT authentication
- PostgreSQL connectivity
- detection-engine connectivity
- environment variables

## Testing

CyberShield contains automated unit and integration tests across the main security and graph-analysis workflows.

Latest verified suite:

```text
140 passed
```

Coverage includes:

- BFS minimum-hop path discovery
- Dijkstra weighted attack paths
- DFS blast-radius analysis
- graph indexing
- critical-asset discovery
- remediation ranking
- MITRE ATT&CK mapping
- event correlation
- UEBA workflows
- prediction workflows
- response approval
- response execution
- audit-chain verification
- API integration workflows

### Deployment Checklist

- [ ] User registration
- [ ] Login and logout
- [ ] Protected routes
- [ ] URL analysis
- [ ] Scan history
- [ ] Email analysis
- [ ] Reconnaissance
- [ ] Threat-feed refresh
- [ ] IOC search
- [ ] MITRE mapping
- [ ] Response approval
- [ ] Automated low-risk response
- [ ] Audit verification
- [ ] WebSocket alerts
- [ ] Admin operations
- [ ] Responsive layout

## Known Limitations

- MITRE mapping currently uses keyword-based classification rather than a complete ATT&CK Navigator integration.
- Threat-feed coverage depends on configured provider API keys.
- Some third-party intelligence services are rate limited or require paid access.
- Network scanning can be restricted in managed cloud environments.
- WebSocket behaviour depends on container and proxy configuration.
- Redis is currently described as supporting low-latency state and caching where configured. The repository does not claim a separately validated distributed queue architecture.
- CyberShield is not intended to replace a production enterprise SIEM, EDR or SOAR platform.

## Roadmap

The following items are planned extensions rather than shipped features.

| Planned Area | Direction |
|---|---|
| MITRE ATT&CK Heatmap | Interactive technique and tactic coverage visualization |
| Behavioural Analytics | Rolling asset baselines and anomaly scoring |
| SIEM Integration | Normalized event output for Sentinel, Splunk or similar systems |
| Threat Actor Context | Confidence-scored IOC correlation |
| Kubernetes | Container orchestration and autoscaling |
| Historical Attack Graphs | Persist graph snapshots and compare path evolution |
| Security Copilot | Read-only LLM assistant constrained by the existing RBAC model |
| Streaming Analytics | Event Hubs or Kafka for higher event volumes |

## Responsible Use

CyberShield is intended for:

- defensive-security learning
- authorized testing
- security engineering demonstrations
- portfolio and research use

Reconnaissance, network scanning and related functionality should only be used against systems you own or have explicit permission to test.

## Documentation

| Resource | Location |
|---|---|
| High-Level Design | [`docs/images/hld.drawio.png`](./docs/images/hld.drawio.png) |
| API Flow | [`docs/images/api-flow.drawio.png`](./docs/images/api-flow.drawio.png) |
| Authentication Flow | [`docs/images/auth-flow.drawio.png`](./docs/images/auth-flow.drawio.png) |
| Feature Workflow | [`docs/images/feature-workflow.drawio.png`](./docs/images/feature-workflow.drawio.png) |
| Response Flow | [`docs/images/response-flow.drawio.png`](./docs/images/response-flow.drawio.png) |
| Threat Pipeline | [`docs/images/threat-pipeline.drawio.png`](./docs/images/threat-pipeline.drawio.png) |
| Editable Diagrams | [`docs/diagrams/`](./docs/diagrams/) |
| System Design | [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md) |
| Evaluation | [`evaluation/`](./evaluation/) |

<div align="center">

## Author

### Agrima Saxena

**Software Engineering · Applied AI · Cybersecurity**

<table align="center">
<tr>

<td align="center" width="70">
<a href="https://www.linkedin.com/in/agrima-saxena-142960426/">
<img src="https://img.icons8.com/color/48/linkedin.png"
     width="32"
     height="32"
     alt="LinkedIn"/>
</a>
</td>

<td align="center" width="70">
<a href="mailto:agrimalc@gmail.com">
<img src="https://img.icons8.com/color/48/gmail-new.png"
     width="32"
     height="32"
     alt="Email"/>
</a>
</td>

<td align="center" width="70">
<a href="https://github.com/agrima08s010315">
<img src="https://img.icons8.com/ios-glyphs/48/ffffff/github.png"
     width="32"
     height="32"
     alt="GitHub"/>
</a>
</td>

</tr>
</table>

<br>

[![Live Demo](https://img.shields.io/badge/Open-CyberShield-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
[![Source](https://img.shields.io/badge/View-Source%20Code-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/agrima08s010315/cybershield-project)

<br><br>

**If you found the project useful, consider leaving a ⭐ on the repository.**

</div>
