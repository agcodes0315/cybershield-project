<div align="center">

# 🛡️ CyberShield

### AI-Assisted Security Operations Center for Critical Infrastructure

A full-stack SOC platform combining **threat intelligence, attack-graph analysis, phishing detection, vulnerability prioritization, MITRE ATT&CK mapping, real-time alerting, and human-governed incident response**.

<br>

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Open%20CyberShield-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
[![GitHub](https://img.shields.io/badge/GitHub-Source%20Code-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/agrima08s010315/cybershield-project)

<br><br>

![React](https://img.shields.io/badge/React-20232A?style=flat&logo=react&logoColor=61DAFB)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat&logo=redis&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-140%20Passing-2EA44F?style=flat&logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

</div>

## Why CyberShield

Modern SOC teams often work across separate tools for phishing analysis, vulnerability management, threat intelligence, malware investigation, and incident response.

CyberShield brings those workflows into one platform.

The system is built as a **multi-service security platform**, not just a dashboard. It separates the frontend, API gateway, detection engine, persistent storage, real-time updates, and response workflows into clear service boundaries.

The project focuses on four engineering areas:

- **Security engineering** through RBAC, threat analysis, audit trails, YARA, MITRE ATT&CK mapping, and analyst approval workflows
- **Backend architecture** through Express.js, FastAPI, PostgreSQL, Redis, REST APIs, and WebSockets
- **Algorithm engineering** through BFS, DFS, Dijkstra, hash-based graph lookups, and remediation ranking
- **Cloud deployment** through Azure Static Web Apps, Azure Container Apps, and Docker

## Engineering Impact

| Area | Result |
|---|---|
| Attack-graph optimization | **~99.97% lower median critical-asset discovery latency** |
| Benchmark scale | **2,500 nodes / 10,000 edges / 125 critical assets** |
| Median latency | **2.46 s → 0.83 ms** |
| Automated validation | **140 passing unit + integration tests** |
| Deployment | **Azure-hosted frontend + backend services** |
| Realtime | **WebSocket-based analyst updates** |
| Security operations | **Human approval + hash-chained audit trail** |

> The performance figures above come from a reproducible synthetic benchmark included in the repository. Absolute timings may vary by hardware and runtime conditions.

## Architecture

CyberShield uses a multi-service architecture with a React frontend, Express.js API gateway, FastAPI detection engine, PostgreSQL, Redis, and Azure deployment.

<p align="center">
  <img src="./docs/images/hld.drawio.png"
       alt="CyberShield High-Level Architecture"
       width="92%">
</p>

<p align="center">
  <sub>High-level service architecture and system boundaries.</sub>
</p>

### Request Flow

<p align="center">
  <img src="./docs/images/api-flow.drawio.png"
       alt="CyberShield API Request Flow"
       width="92%">
</p>

The API gateway handles authentication, routing, authorization, and request validation before requests reach downstream services.

### Authentication Flow

<p align="center">
  <img src="./docs/images/auth-flow.drawio.png"
       alt="CyberShield Authentication Flow"
       width="90%">
</p>

JWT-based authentication and role-aware authorization are applied before protected actions reach the detection layer.

### Deployment Architecture

<p align="center">
  <img src="./docs/images/deployment_architecture.drawio.png"
       alt="CyberShield Deployment Architecture"
       width="92%">
</p>

The frontend and backend services are deployed independently so they can scale and evolve separately.

## Core Capabilities

<table>
<tr>

<td width="50%" valign="top">

### 🔎 Threat Intelligence

- suspicious URL analysis
- domain and IP reputation
- email header inspection
- SPF / DKIM / DMARC validation
- reconnaissance workflows
- external threat intelligence connectors

</td>

<td width="50%" valign="top">

### 🕸️ Attack Graph Intelligence

- BFS minimum-hop paths
- Dijkstra weighted paths
- DFS blast-radius analysis
- critical-asset discovery
- containment simulation
- remediation prioritization

</td>

</tr>

<tr>

<td width="50%" valign="top">

### 🛡️ Security Operations

- SOC command center
- incident lifecycle tracking
- threat feed dashboards
- WebSocket alerts
- analyst workspace
- risk-aware investigation workflows

</td>

<td width="50%" valign="top">

### ⚙️ Response Orchestration

- automated low-risk playbooks
- human approval for higher-risk actions
- response execution history
- hash-chained audit records
- cyber resilience analysis

</td>

</tr>
</table>

## System Design

### Entity Relationship Model

<p align="center">
  <img src="./docs/images/ER_Diagram_Clean.drawio.png"
       alt="CyberShield Entity Relationship Diagram"
       width="90%">
</p>

### Feature Workflow

<p align="center">
  <img src="./docs/images/feature-workflow.drawio.png"
       alt="CyberShield Feature Workflow"
       width="92%">
</p>

### Threat Processing Pipeline

<p align="center">
  <img src="./docs/images/threat-pipeline.drawio.png"
       alt="CyberShield Threat Processing Pipeline"
       width="92%">
</p>

### Response Flow

<p align="center">
  <img src="./docs/images/response-flow.drawio.png"
       alt="CyberShield Response Flow"
       width="92%">
</p>

Editable Draw.io files are available in [`docs/diagrams/`](./docs/diagrams/).

Detailed design notes are available in [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md).

## Algorithm Engineering

CyberShield models infrastructure assets and trust relationships as a directed weighted graph.

The attack-graph subsystem uses:

- **BFS** for minimum-hop attack paths
- **Dijkstra's algorithm** for lowest-cost weighted paths
- **DFS** for blast-radius and compromise reachability
- **hash maps and sets** for constant-time average membership lookup
- **priority queues** for remediation ranking
- **adjacency lists** for graph representation

### Critical-Asset Discovery Optimization

The original implementation executed Dijkstra independently for each critical asset.

For `K` critical assets:

```text
O(K × (V + E) log V)
```

The implementation was redesigned around a single-source shortest-path traversal combined with hash-set membership checks.

The optimized approximation becomes:

```text
O((V + E) log V + K)
```

### Benchmark

| Metric | Before | After |
|---|---:|---:|
| Nodes | 2,500 | 2,500 |
| Edges | 10,000 | 10,000 |
| Critical assets | 125 | 125 |
| Mean latency | 2434.16 ms | 0.84 ms |
| Median latency | 2461.10 ms | 0.83 ms |
| P95 latency | 2582.02 ms | 0.90 ms |

**Median critical-asset discovery latency fell from approximately 2.46 seconds to 0.83 milliseconds in the recorded benchmark.**

That is approximately a **99.97% reduction in median latency**.

Benchmark artifacts are included under:

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

## Backend & Security Design

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

Each important transition is recorded in the audit log.

### Audit Trail

The audit log stores fields including:

```text
incident_id
actor
action
payload_hash
prev_hash
timestamp
```

Each record references the previous record hash.

This allows unexpected historical modifications to be detected during chain verification.

### RBAC

| Role | View Incidents | Run Playbook | Approve High-Risk Action | Manage Users |
|---|:---:|:---:|:---:|:---:|
| Analyst | ✅ | ❌ | ❌ | ❌ |
| Senior Analyst | ✅ | ✅ Low Risk | ✅ | ❌ |
| SOC Lead | ✅ | ✅ | ✅ | ✅ |

Authorization is enforced at the API gateway before protected operations reach downstream services.

### Rate Limiting

| Endpoint | Limit |
|---|---:|
| `/scan/url` | 30 req/min per analyst |
| `/scan/email` | 20 req/min per analyst |
| `/orchestrator/execute` | 5 req/min per analyst |
| `/auth/*` | 10 req/min per IP |

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Axios, Recharts, Lucide React |
| API Gateway | Node.js, Express.js, JWT, Helmet, CORS |
| Detection Engine | Python, FastAPI, scikit-learn, YARA, Nmap, WHOIS |
| Database | PostgreSQL |
| Caching / State | Redis |
| Realtime | WebSockets |
| Cloud | Microsoft Azure |
| Deployment | Static Web Apps, Container Apps, Docker |
| Testing | pytest, unit tests, integration tests |

## Implemented Modules

| Module | Purpose |
|---|---|
| SOC Dashboard | Central operational dashboard |
| URL Scanner | Suspicious URL analysis |
| Email Analyzer | Header and spoofing analysis |
| Reconnaissance | Domain and network intelligence |
| MITRE ATT&CK Mapping | Technique and tactic mapping |
| Attack Graph | Attack path and blast-radius analysis |
| Breach Checker | Exposure verification |
| Pen Testing | Controlled security assessment |
| YARA Scanner | Malware rule matching |
| GoPhish Simulator | Awareness campaigns |
| Cyber Resilience | Risk and resilience analysis |
| Response Orchestrator | Incident response coordination |
| SOC Community | Threat intelligence collaboration |
| Settings | Workspace configuration |

## AI & Analytics

CyberShield uses ML and analytics selectively rather than labeling every feature as AI.

Current areas include:

- phishing URL classification
- behaviour-based risk signals
- vulnerability prioritization
- security event correlation
- email spoofing analysis
- incident recommendation support
- resilience scoring

## Testing

CyberShield includes automated unit and integration coverage across graph algorithms, response workflows, audit verification, MITRE ATT&CK mapping, event correlation, and API behavior.

Latest verified run:

```text
140 passed
```

Coverage includes:

- BFS pathfinding
- Dijkstra weighted paths
- DFS blast-radius analysis
- graph indexing
- critical-asset discovery
- remediation ranking
- MITRE ATT&CK mapping
- event correlation
- UEBA workflows
- response approvals
- response execution
- audit-chain verification
- API integration flows

## Live Deployment

| Component | Deployment |
|---|---|
| Frontend | [Azure Static Web Apps](https://mango-pebble-099d8de00.7.azurestaticapps.net/) |
| API Gateway | [Azure Container App](https://cybershield-api-gateway.niceforest-87cbfff3.centralindia.azurecontainerapps.io) |
| Detection Engine | Azure Container App |
| Database | PostgreSQL |
| Realtime | WebSockets |

## API Examples

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

FastAPI also exposes interactive documentation at:

```text
/docs
```

## Local Setup

### Requirements

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

Windows:

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

Run:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```bash
cd client
npm install
npm run dev
```

Open:

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

Do not commit real secrets or production API keys.

## Repository Structure

```text
CyberShield/
|
├── client/
│   └── src/
|
├── api-gateway/
│   ├── middleware/
│   ├── routes/
│   └── utils/
|
├── detection-engine/
│   ├── app/
│   │   └── attack_graph/
│   ├── models/
│   └── rules/
|
├── docs/
│   ├── diagrams/
│   ├── images/
│   └── SYSTEM_DESIGN.md
|
├── evaluation/
│   ├── baselines/
│   ├── benchmark_graph_algorithms.py
│   ├── graph_algorithm_benchmark_before.csv
│   ├── graph_algorithm_benchmark_after.csv
│   └── graph_algorithm_verified_run.txt
|
├── tests/
│   ├── unit/
│   ├── integration/
│   └── scenarios/
|
├── docker-compose.yml
└── README.md
```

## Known Limitations

CyberShield is an engineering and portfolio project, not a replacement for a production SIEM, SOAR, EDR, or enterprise threat-intelligence platform.

Current limitations include:

- MITRE mapping uses keyword-based classification rather than a full Navigator integration
- third-party threat intelligence depends on available API keys
- external services may be rate limited
- managed cloud environments can restrict network scanning
- WebSocket behaviour depends on proxy/container configuration
- Redis is used for low-latency state and caching where configured, but the repository does not claim a separately validated distributed queue architecture

## Roadmap

| Area | Planned Direction |
|---|---|
| MITRE Visualization | ATT&CK Navigator-style coverage heatmap |
| Behaviour Analytics | Rolling asset baselines and anomaly scoring |
| SIEM Integration | Normalized events for Sentinel or Splunk |
| Threat Actor Context | Confidence-scored IOC correlation |
| Historical Attack Graphs | Persist attack-path evolution |
| Security Copilot | Read-only assistant constrained by RBAC |
| Kubernetes | Container orchestration and autoscaling |
| Streaming Analytics | Event Hubs or Kafka for larger workloads |

## Responsible Use

CyberShield is intended for **defensive-security learning, authorized testing, research, and portfolio use**.

Reconnaissance and network scanning features should only be used against systems you own or have explicit permission to test.

## Documentation

| Resource | Link |
|---|---|
| High-Level Design | [`docs/images/hld.drawio.png`](./docs/images/hld.drawio.png) |
| API Flow | [`docs/images/api-flow.drawio.png`](./docs/images/api-flow.drawio.png) |
| Authentication Flow | [`docs/images/auth-flow.drawio.png`](./docs/images/auth-flow.drawio.png) |
| Feature Workflow | [`docs/images/feature-workflow.drawio.png`](./docs/images/feature-workflow.drawio.png) |
| Response Flow | [`docs/images/response-flow.drawio.png`](./docs/images/response-flow.drawio.png) |
| Threat Pipeline | [`docs/images/threat-pipeline.drawio.png`](./docs/images/threat-pipeline.drawio.png) |
| Editable Draw.io Files | [`docs/diagrams/`](./docs/diagrams/) |
| System Design | [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md) |
| Evaluation Artifacts | [`evaluation/`](./evaluation/) |

<div align="center">

## Author

### Agrima Saxena

**Software Engineering · Backend Systems · Applied AI · Cybersecurity**

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
[![Source Code](https://img.shields.io/badge/View-Source%20Code-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/agrima08s010315/cybershield-project)

<br><br>

**Built to explore how security analytics, backend systems, graph algorithms, and analyst-controlled response can work together in one platform.**

</div>
