# 🛡️ CyberShield

### AI-Assisted Security Operations Center Platform for Critical Infrastructure

CyberShield is a full-stack security operations platform that brings together **threat intelligence, phishing detection, vulnerability prioritization, attack-graph analysis, incident response, MITRE ATT&CK mapping, and analyst-governed remediation** in one workflow.

Built with **React, Node.js, FastAPI, PostgreSQL, Redis, WebSockets, and Azure**, the project focuses on both security functionality and the engineering behind it: service boundaries, graph algorithms, performance optimization, testing, auditability, and cloud deployment.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Azure-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
[![Repository](https://img.shields.io/badge/GitHub-Repository-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/agrima08s010315/cybershield-project)
![Tests](https://img.shields.io/badge/Tests-140%20Passing-2EA44F?style=flat-square&logo=pytest&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=flat-square&logo=react&logoColor=61DAFB)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat-square&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)

## 🚀 What CyberShield Does

Modern security teams often rely on separate tools for phishing analysis, threat intelligence, vulnerability management, malware inspection, attack-path analysis, and incident response.

CyberShield connects those workflows into a single SOC-style platform.

An analyst can:

- inspect suspicious URLs, domains, IPs, and email headers
- analyze infrastructure attack paths
- map findings to MITRE ATT&CK
- prioritize vulnerable or critical assets
- investigate YARA and IOC matches
- receive real-time WebSocket alerts
- review recommended response actions
- approve high-risk remediation manually
- verify the complete incident history through an audit trail

The goal is not to replicate an enterprise SIEM product feature-for-feature. The project instead explores how the core pieces of a modern security operations platform can be designed and connected in one understandable system.

## 📊 Engineering Highlights

| Area | Result |
|---|---|
| Graph optimization | **~99.97% lower median latency** |
| Before optimization | **2461.10 ms** |
| After optimization | **0.83 ms** |
| Benchmark graph | **2,500 nodes / 10,000 edges** |
| Critical assets | **125** |
| Automated tests | **140 passing** |
| Realtime updates | **WebSockets** |
| Cloud deployment | **Microsoft Azure** |
| Response model | **Human approval for higher-risk actions** |

## 🧩 Why This Project Matters

Security platforms are not only about detecting threats.

A useful SOC platform must also answer:

- What systems are affected?
- How can an attacker move through the environment?
- Which assets matter most?
- Which findings should be handled first?
- What remediation is safe to automate?
- Which action requires a human decision?
- Can the organization reconstruct what happened later?

CyberShield was built around those questions.

## 🏗️ System Architecture

CyberShield uses a multi-service architecture.

The React frontend communicates with the Express API gateway. The gateway handles authentication, authorization, routing, rate limiting, and access control. Analysis workloads are handled by the FastAPI detection engine.

PostgreSQL stores persistent application state. Redis is used for low-latency state and caching where configured. WebSockets provide real-time analyst updates.

<p align="center">
  <img src="./docs/images/hld.drawio.png"
       alt="CyberShield High-Level Design"
       width="92%">
</p>

<p align="center">
  <sub>High-level architecture and service boundaries.</sub>
</p>

### API Request Flow

<p align="center">
  <img src="./docs/images/api-flow.drawio.png"
       alt="CyberShield API Flow"
       width="92%">
</p>

Requests are routed through the API gateway before they reach backend services.

This keeps authentication and access-control decisions outside the detection engine.

### Authentication Flow

<p align="center">
  <img src="./docs/images/auth-flow.drawio.png"
       alt="CyberShield Authentication Flow"
       width="90%">
</p>

Protected workflows use JWT-based authentication with role-aware authorization.

### Deployment Architecture

<p align="center">
  <img src="./docs/images/deployment_architecture.drawio.png"
       alt="CyberShield Deployment Architecture"
       width="92%">
</p>

The frontend and backend services are deployed independently to make the platform easier to scale and update.

## 🔍 How a Threat Moves Through CyberShield

```text
Security Input
     |
     v
API Gateway
     |
     v
Authentication + RBAC
     |
     v
Detection / Analysis
     |
     +---------> Threat Intelligence
     |
     +---------> Attack Graph
     |
     +---------> MITRE ATT&CK
     |
     +---------> Vulnerability Context
     |
     v
Risk Evaluation
     |
     v
Response Recommendation
     |
     +-------- Low Risk --------> Automated Playbook
     |
     +-------- Higher Risk -----> Human Approval
                                    |
                                    v
                               Response Action
                                    |
                                    v
                                Audit Trail
```

## ✨ Core Features

### 🔎 Threat Intelligence

CyberShield brings multiple investigation signals into one workflow.

- URL analysis
- IP reputation
- domain intelligence
- SSL information
- WHOIS inspection
- IOC search
- external threat-feed connectors
- phishing analysis

### 📧 Email Security

The email-analysis workflow supports:

- header inspection
- SPF validation
- DKIM checks
- DMARC checks
- sender-domain analysis
- spoofing indicators

### 🕸️ Attack Graph Intelligence

Infrastructure is represented as a directed weighted graph.

The attack-graph subsystem supports:

- BFS minimum-hop paths
- Dijkstra lowest-cost paths
- DFS blast-radius analysis
- critical-asset discovery
- compromise reachability
- remediation prioritization
- containment simulation

### 🧯 Incident Response

Response workflows distinguish between actions that can be automated and actions that should require explicit analyst approval.

- automated low-risk playbooks
- analyst approval workflows
- incident-state transitions
- remediation history
- response orchestration
- audit logging

### 🦠 Malware Analysis

- YARA rules
- IOC detection
- signature-based analysis

### 🧭 MITRE ATT&CK

Findings can be mapped to ATT&CK techniques and tactics to provide additional context around the stage of an attack.

## 🧠 Algorithm Engineering

One of the main engineering improvements in CyberShield was made inside the attack-graph subsystem.

### Original Approach

The initial critical-asset discovery implementation ran Dijkstra's algorithm independently for every critical asset.

With `K` critical assets:

```text
O(K × (V + E) log V)
```

This worked correctly, but scaled poorly as the number of critical assets increased.

### Optimized Approach

The implementation was redesigned to perform a single-source shortest-path traversal and use hash-set membership checks while evaluating critical assets.

Approximate complexity:

```text
O((V + E) log V + K)
```

### Benchmark Results

The before and after implementations were evaluated using the same deterministic synthetic graph.

| Metric | Before | After |
|---|---:|---:|
| Nodes | 2,500 | 2,500 |
| Edges | 10,000 | 10,000 |
| Critical assets | 125 | 125 |
| Mean latency | 2434.16 ms | 0.84 ms |
| Median latency | 2461.10 ms | 0.83 ms |
| P95 latency | 2582.02 ms | 0.90 ms |

**Median latency decreased from approximately 2.46 seconds to 0.83 milliseconds in the recorded benchmark.**

That represents an approximate:

## **99.97% reduction in median critical-asset discovery latency**

The optimization was also validated against the complete test suite:

```text
140 passed
```

Benchmark artifacts are stored under:

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

## 🔎 Low-Level Design

### Entity Relationship Model

<p align="center">
  <img src="./docs/images/ER_Diagram_Clean.drawio.png"
       alt="CyberShield Entity Relationship Diagram"
       width="90%">
</p>

The persistent data layer includes entities for:

- users
- roles
- incidents
- findings
- audit records
- operational state

### Feature Workflow

<p align="center">
  <img src="./docs/images/feature-workflow.drawio.png"
       alt="CyberShield Feature Workflow"
       width="92%">
</p>

### Threat Pipeline

<p align="center">
  <img src="./docs/images/threat-pipeline.drawio.png"
       alt="CyberShield Threat Processing Pipeline"
       width="92%">
</p>

### Response Flow

<p align="center">
  <img src="./docs/images/response-flow.drawio.png"
       alt="CyberShield Response Workflow"
       width="92%">
</p>

Editable Draw.io source files are available in:

[`docs/diagrams/`](./docs/diagrams/)

Full system-design notes are available in:

[`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md)

## 🔐 Authentication and RBAC

CyberShield uses JWT authentication with role-based authorization.

| Role | View Incidents | Run Playbook | Approve High-Risk Action | Manage Users |
|---|:---:|:---:|:---:|:---:|
| Analyst | ✅ | ❌ | ❌ | ❌ |
| Senior Analyst | ✅ | ✅ Low Risk | ✅ | ❌ |
| SOC Lead | ✅ | ✅ | ✅ | ✅ |

Authorization is enforced at the API gateway before protected requests reach downstream services.

## 🧾 Auditable Incident Lifecycle

CyberShield records important incident transitions instead of storing only the latest state.

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

Audit records contain information such as:

```text
incident_id
actor
action
payload_hash
previous_hash
timestamp
```

Records are hash-chained using the previous record's hash.

This allows the application to detect whether historical audit entries have been modified unexpectedly.

## ⚡ Real-Time SOC Updates

CyberShield uses WebSockets to push updates to connected analyst sessions.

Examples include:

- newly created incidents
- approval requests
- completed playbooks
- threat-analysis results
- response-state changes

This avoids relying only on dashboard polling.

## 🛡️ Security Controls

The application includes:

- JWT authentication
- BCrypt password hashing
- role-based access control
- request validation
- rate limiting
- Helmet security headers
- CORS restrictions
- parameterized SQL queries
- human approval for higher-risk actions
- hash-chained audit records
- secure cloud deployment

### Rate Limits

| Endpoint | Limit |
|---|---:|
| `/scan/url` | 30 requests/min per analyst |
| `/scan/email` | 20 requests/min per analyst |
| `/orchestrator/execute` | 5 requests/min per analyst |
| `/auth/*` | 10 requests/min per IP |

## 🤖 AI and Analytics

CyberShield uses machine learning and analytics where they provide useful decision support.

Current workflows include:

| Capability | Purpose |
|---|---|
| URL analysis | suspicious URL classification |
| Phishing detection | identify phishing indicators |
| Vulnerability prioritization | rank findings using context |
| Event correlation | connect related security events |
| Behaviour analysis | identify unusual activity |
| Incident recommendation | suggest response direction |
| Resilience scoring | summarize organizational security posture |

The system does not treat AI output as an automatic authority for high-impact response actions.

Higher-risk remediation remains analyst-controlled.

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Axios, Recharts, Lucide React |
| API Gateway | Node.js, Express.js |
| Detection Engine | Python, FastAPI |
| ML | scikit-learn |
| Graph Analysis | BFS, DFS, Dijkstra |
| Malware Analysis | YARA |
| Reconnaissance | Nmap, WHOIS |
| Database | PostgreSQL |
| Cache / State | Redis |
| Realtime | WebSockets |
| Authentication | JWT, BCrypt |
| Cloud | Microsoft Azure |
| Containers | Docker |
| Testing | pytest |

## 📦 Implemented Modules

| Module | Description |
|---|---|
| SOC Dashboard | operational security overview |
| URL Scanner | suspicious URL analysis |
| Email Analyzer | authentication and spoofing analysis |
| Reconnaissance | domain and network intelligence |
| Threat Intelligence | IOC and reputation analysis |
| MITRE ATT&CK | technique and tactic mapping |
| Attack Graph | paths, reachability and blast radius |
| Vulnerability Management | prioritization and risk scoring |
| Breach Checker | credential exposure verification |
| YARA Scanner | malware rule matching |
| GoPhish Simulator | awareness workflows |
| Response Orchestrator | incident response coordination |
| Audit Engine | action and state history |
| Cyber Resilience | security posture analytics |
| SOC Community | shared threat intelligence |
| Settings | workspace configuration |

## 📡 API Surface

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
<summary><b>Incident Response</b></summary>

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

## 📁 Repository Structure

```text
CyberShield/
|
├── client/
│   └── src/
│       ├── components/
│       ├── context/
│       ├── hooks/
│       ├── pages/
│       └── services/
|
├── api-gateway/
│   ├── config/
│   ├── middleware/
│   ├── routes/
│   └── utils/
|
├── detection-engine/
│   ├── app/
│   │   └── attack_graph/
│   │       ├── graph.py
│   │       ├── pathfinder.py
│   │       ├── blast_radius.py
│   │       └── remediation.py
│   ├── models/
│   └── rules/
|
├── docs/
│   ├── diagrams/
│   ├── images/
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

## ⚙️ Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/agrima08s010315/cybershield-project.git
cd cybershield-project
```

### 2. Start the API Gateway

```bash
cd api-gateway
npm install
npm run dev
```

### 3. Start the Detection Engine

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

Run FastAPI:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 4. Start the Frontend

```bash
cd client
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## 🔑 Environment Variables

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

Do not commit production secrets or provider API keys.

## ☁️ Azure Deployment

| Component | Deployment |
|---|---|
| Frontend | Azure Static Web Apps |
| API Gateway | Azure Container Apps |
| Detection Engine | Azure Container Apps |
| Containers | Docker |

Production checks include:

```http
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```

Deployment validation should also cover:

- HTTPS
- WSS WebSockets
- CORS
- authentication
- PostgreSQL connectivity
- detection-engine connectivity
- environment configuration

## 🧪 Testing

CyberShield includes automated tests across graph analysis, incident workflows, security analytics, API behaviour, and audit integrity.

Latest verified run:

```text
140 passed
```

Coverage includes:

- BFS minimum-hop paths
- Dijkstra weighted attack paths
- DFS blast-radius analysis
- graph indexing
- critical-asset discovery
- remediation ranking
- MITRE ATT&CK mapping
- event correlation
- UEBA workflows
- prediction workflows
- response approvals
- response execution
- audit-chain integrity
- API integration workflows

## 🔬 Reproducibility

Performance benchmark artifacts are committed under `evaluation/`.

This makes it possible to inspect:

- the benchmark generator
- before/after implementations
- raw CSV output
- the verified benchmark run

The performance figures in this README refer to those recorded experiments rather than estimated values.

## ⚠️ Known Limitations

CyberShield is a portfolio and defensive-security engineering project, not a production replacement for Sentinel, Splunk, CrowdStrike, or a commercial SOAR platform.

Current limitations include:

- MITRE mapping currently uses keyword-oriented classification
- threat-feed coverage depends on configured provider APIs
- external intelligence services may be rate limited
- network scanning can be restricted in cloud environments
- WebSocket behaviour depends on proxy/container configuration
- Redis is currently used for low-latency state/caching where configured
- distributed queue behaviour has not been independently benchmarked end-to-end

## 🌱 Roadmap

| Area | Planned Direction |
|---|---|
| ATT&CK Visualization | interactive ATT&CK coverage heatmap |
| Behaviour Analytics | rolling asset baselines and anomaly scoring |
| SIEM Integration | normalized event export for Sentinel / Splunk |
| Threat Actor Context | confidence-scored IOC correlation |
| Historical Attack Graphs | graph snapshots and path evolution |
| Security Copilot | read-only RBAC-constrained assistant |
| Kubernetes | AKS-based service orchestration |
| Streaming Analytics | Event Hubs / Kafka for higher event volumes |

## 🎯 What This Project Demonstrates

CyberShield is primarily an exercise in connecting several software-engineering concerns inside one system:

- **backend architecture**
- **API design**
- **graph algorithms**
- **performance optimization**
- **security engineering**
- **machine learning integration**
- **role-based authorization**
- **real-time communication**
- **testing**
- **cloud deployment**
- **human-in-the-loop decision workflows**

## 📚 Documentation

| Resource | Location |
|---|---|
| High-Level Architecture | [`docs/images/hld.drawio.png`](./docs/images/hld.drawio.png) |
| API Flow | [`docs/images/api-flow.drawio.png`](./docs/images/api-flow.drawio.png) |
| Authentication Flow | [`docs/images/auth-flow.drawio.png`](./docs/images/auth-flow.drawio.png) |
| Entity Relationship Diagram | [`docs/images/ER_Diagram_Clean.drawio.png`](./docs/images/ER_Diagram_Clean.drawio.png) |
| Feature Workflow | [`docs/images/feature-workflow.drawio.png`](./docs/images/feature-workflow.drawio.png) |
| Response Flow | [`docs/images/response-flow.drawio.png`](./docs/images/response-flow.drawio.png) |
| Threat Pipeline | [`docs/images/threat-pipeline.drawio.png`](./docs/images/threat-pipeline.drawio.png) |
| Editable Draw.io Files | [`docs/diagrams/`](./docs/diagrams/) |
| System Design Notes | [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md) |
| Evaluation Artifacts | [`evaluation/`](./evaluation/) |

## 📄 Responsible Use

CyberShield is intended for:

- defensive-security learning
- authorized testing
- security engineering demonstrations
- portfolio and research use

Only run reconnaissance, scanning, or security-testing functionality against systems you own or have explicit permission to assess.

## 👩‍💻 Author

### Agrima Saxena

**Software Engineering · Applied AI · Cybersecurity**

<br>

<table>
  <tr>
    <td width="60">
      <a href="https://www.linkedin.com/in/agrima-saxena-142960426/" title="LinkedIn">
        <img src="https://img.icons8.com/color/48/linkedin.png"
             width="34"
             height="34"
             alt="LinkedIn"/>
      </a>
    </td>

    <td width="60">
      <a href="mailto:agrimalc@gmail.com" title="Email">
        <img src="https://img.icons8.com/color/48/gmail-new.png"
             width="34"
             height="34"
             alt="Email"/>
      </a>
    </td>

    <td width="60">
      <a href="https://github.com/agrima08s010315" title="GitHub">
        <img src="https://img.icons8.com/ios-glyphs/48/ffffff/github.png"
             width="34"
             height="34"
             alt="GitHub"/>
      </a>
    </td>
  </tr>
</table>

<br>

<a href="https://mango-pebble-099d8de00.7.azurestaticapps.net/">
  <img src="https://img.shields.io/badge/Live%20Demo-Open%20CyberShield-0078D4?style=flat-square&logo=microsoftazure&logoColor=white"
       alt="CyberShield Live Demo"/>
</a>

<a href="https://github.com/agrima08s010315/cybershield-project">
  <img src="https://img.shields.io/badge/GitHub-View%20Repository-181717?style=flat-square&logo=github&logoColor=white"
       alt="CyberShield Repository"/>
</a>

<br><br>

⭐ **If you found CyberShield useful or interesting, consider starring the repository.**

