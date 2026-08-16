# 🛡️ CyberShield

## AI-Assisted Security Operations Center Platform

CyberShield is a full-stack SOC platform designed to bring **threat intelligence, phishing detection, attack-graph analysis, vulnerability prioritization, MITRE ATT&CK mapping, incident response, and analyst-governed remediation** into one operational workflow.

It is built as a modular, cloud-ready system using **React, Express.js, FastAPI, PostgreSQL, Redis, WebSockets, and Azure**.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-CyberShield-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
[![Repository](https://img.shields.io/badge/GitHub-Source%20Code-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/agrima08s010315/cybershield-project)
![Tests](https://img.shields.io/badge/Tests-140%20Passing-2EA44F?style=flat-square&logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)

## 🚀 Why This Project

Modern security teams work across many disconnected tools for phishing analysis, threat feeds, vulnerability assessment, malware detection, network reconnaissance, and response.

CyberShield explores what that workflow looks like when these capabilities are brought together into one system.

The platform focuses on:

- centralized security operations
- attack-path reasoning
- real-time analyst visibility
- response governance
- measurable algorithm performance
- auditability
- modular service architecture

## ✨ Engineering Highlights

- Built a multi-service SOC platform using **React, Express.js, FastAPI, PostgreSQL, and Redis**
- Implemented attack-graph intelligence using **BFS, DFS, and Dijkstra's algorithm**
- Reworked critical-asset discovery to reduce median benchmark latency from **~2.46 s to ~0.83 ms**
- Achieved an approximate **99.97% reduction in median latency** in the recorded benchmark
- Benchmarked against a deterministic **2,500-node / 10,000-edge synthetic attack graph**
- Maintained **140 passing automated unit and integration tests**
- Added real-time security updates using **WebSockets**
- Integrated **YARA, SSL/WHOIS analysis, threat feeds, and MITRE ATT&CK mapping**
- Added analyst-controlled response workflows and hash-chained audit records
- Deployed the frontend and backend services on **Microsoft Azure**

## 🧩 Core Capabilities

| Area | What CyberShield Does |
|---|---|
| SOC Operations | Central dashboard, security monitoring, analyst workspace |
| Threat Intelligence | URL analysis, email analysis, IP/domain reputation, threat feeds |
| Attack Graphs | BFS, DFS, Dijkstra, blast radius, critical-asset discovery |
| Vulnerability Management | Risk scoring, prioritization, asset criticality |
| Malware Analysis | YARA rule scanning and IOC matching |
| Response | Human approval, automated low-risk playbooks, action history |
| MITRE ATT&CK | Technique and tactic mapping |
| Cyber Resilience | Event correlation, risk context, resilience analysis |
| Collaboration | Shared threat intelligence and analyst workflows |

## 🏗️ System Architecture

CyberShield follows a multi-service architecture.

The **React frontend** communicates with an **Express API Gateway**, which handles authentication, authorization, routing, and API controls.

The **FastAPI detection engine** handles analysis workloads.

**PostgreSQL** stores persistent application data, while **Redis** supports low-latency application state and caching where configured.

<p align="left">
  <img src="./docs/images/hld.drawio.png"
       alt="CyberShield High Level Design"
       width="88%">
</p>

### API Flow

<p align="left">
  <img src="./docs/images/api-flow.drawio.png"
       alt="CyberShield API Flow"
       width="88%">
</p>

### Authentication Flow

<p align="left">
  <img src="./docs/images/auth-flow.drawio.png"
       alt="CyberShield Authentication Flow"
       width="88%">
</p>

### Deployment Architecture

<p align="left">
  <img src="./docs/images/deployment_architecture.drawio.png"
       alt="CyberShield Deployment Architecture"
       width="88%">
</p>

Editable architecture diagrams are available in [`docs/diagrams/`](./docs/diagrams/).

More system-design documentation is available in [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md).

## 🔎 Low-Level Design

### Entity Relationship Model

<p align="left">
  <img src="./docs/images/ER_Diagram_Clean.drawio.png"
       alt="CyberShield Entity Relationship Diagram"
       width="86%">
</p>

### Feature Workflow

<p align="left">
  <img src="./docs/images/feature-workflow.drawio.png"
       alt="CyberShield Feature Workflow"
       width="88%">
</p>

### Threat Processing Pipeline

<p align="left">
  <img src="./docs/images/threat-pipeline.drawio.png"
       alt="CyberShield Threat Pipeline"
       width="88%">
</p>

### Response Flow

<p align="left">
  <img src="./docs/images/response-flow.drawio.png"
       alt="CyberShield Response Flow"
       width="88%">
</p>

## 🧮 Algorithm Engineering

CyberShield models infrastructure assets and trust relationships as a directed weighted graph.

The attack-graph subsystem uses:

| Algorithm / Structure | Purpose |
|---|---|
| BFS | Minimum-hop attack paths |
| Dijkstra | Lowest-cost attack paths |
| DFS | Blast-radius and compromise reachability |
| Hash Maps / Sets | Asset and membership lookup |
| Priority Queue | Remediation ranking |
| Adjacency Lists | Memory-efficient graph storage |

### Critical-Asset Discovery Optimization

The earlier implementation independently ran Dijkstra for each critical asset.

Approximate complexity:

```text
O(K × (V + E) log V)
```

where `K` is the number of critical assets.

The implementation was redesigned around a single-source shortest-path traversal and hash-set membership checks.

Approximate complexity:

```text
O((V + E) log V + K)
```

### Reproducible Benchmark

| Metric | Before | After |
|---|---:|---:|
| Graph Nodes | 2,500 | 2,500 |
| Graph Edges | 10,000 | 10,000 |
| Critical Assets | 125 | 125 |
| Mean Latency | 2434.16 ms | 0.84 ms |
| Median Latency | 2461.10 ms | 0.83 ms |
| P95 Latency | 2582.02 ms | 0.90 ms |

**Recorded median latency decreased from ~2.46 seconds to ~0.83 milliseconds.**

That corresponds to approximately **99.97% lower median latency** for the benchmarked operation.

The optimization was also validated against the complete test suite:

```text
140 passed
```

Evaluation artifacts:

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Axios, Recharts, Lucide React |
| API Gateway | Node.js, Express.js, JWT, Helmet, CORS, Rate Limiting |
| Detection Engine | Python, FastAPI, scikit-learn, YARA, Nmap, WHOIS |
| Database | PostgreSQL |
| Caching / State | Redis |
| Realtime | WebSockets |
| Cloud | Microsoft Azure |
| Deployment | Static Web Apps, Container Apps, Docker |
| Testing | pytest, unit testing, integration testing |

## 🧠 AI & Analytics

CyberShield uses ML and security analytics in selected workflows.

Current capabilities include:

- phishing URL analysis
- threat intelligence correlation
- email spoofing detection
- vulnerability prioritization
- behavioural risk signals
- event correlation
- incident recommendation support
- cyber-resilience scoring

## 🔐 Security Controls

The platform includes:

- JWT authentication
- BCrypt password hashing
- role-based access control
- input validation
- rate limiting
- parameterized SQL
- human approval for higher-risk actions
- hash-chained audit records
- protected API routes
- secure Azure deployment

## 👥 Role-Based Access Control

| Role | View Incidents | Run Playbook | Approve High-Risk Action | Manage Users |
|---|:---:|:---:|:---:|:---:|
| Analyst | ✅ | ❌ | ❌ | ❌ |
| Senior Analyst | ✅ | ✅ Low Risk | ✅ | ❌ |
| SOC Lead | ✅ | ✅ | ✅ | ✅ |

## 📋 Incident Lifecycle

```text
Detected
   |
   v
Triaged
   |
   v
Playbook Run
   |
   +----> Rejected
   |
   v
Human Approved
   |
   v
Closed
```

Important state transitions are written into the audit trail so that an incident can be reconstructed from its history.

## 📡 Real-Time Workflow

The API Gateway maintains WebSocket connections for active analyst sessions.

Security events such as:

- new incidents
- response completion
- approval requests
- threat updates

can be pushed to connected clients without requiring constant polling.

## 📂 Project Structure

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
│   └── server.js
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

## 📡 API Endpoints

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

Interactive FastAPI documentation is available at:

```text
/docs
```

## ⚙️ Local Setup

### 1. Clone

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

Start FastAPI:

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

Do not commit production secrets or real third-party API keys.

## ☁️ Azure Deployment

| Component | Azure Service |
|---|---|
| Frontend | Azure Static Web Apps |
| API Gateway | Azure Container Apps |
| Detection Engine | Azure Container Apps |
| Packaging | Docker |

Useful health checks include:

```http
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```

## 🧪 Testing

Latest verified test run:

```text
140 passed
```

Coverage includes:

- BFS minimum-hop paths
- Dijkstra weighted paths
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

## ⚠️ Current Limitations

- MITRE mapping uses keyword-based classification rather than full ATT&CK Navigator integration.
- Threat-feed coverage depends on provider API keys.
- Some third-party services are rate limited or paid.
- Network scanning can be restricted in cloud environments.
- WebSocket behaviour depends on proxy and container configuration.
- Redis is currently used for low-latency state and caching where configured.
- CyberShield is a portfolio and defensive-security engineering project, not a production replacement for a commercial SIEM or EDR.

## 🌱 Planned Improvements

| Area | Direction |
|---|---|
| MITRE Heatmap | Interactive ATT&CK coverage visualization |
| Behaviour Analytics | Per-asset behavioural baselines |
| SIEM Integration | Normalized event export for Sentinel or Splunk |
| Historical Graph Analysis | Persist and compare attack-path changes |
| Kubernetes | Service orchestration and autoscaling |
| Security Copilot | Read-only LLM assistant constrained by RBAC |
| Streaming Analytics | Event Hubs or Kafka for larger event volumes |

## 📚 Documentation

| Resource | Link |
|---|---|
| System Design | [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md) |
| High-Level Design | [`docs/images/hld.drawio.png`](./docs/images/hld.drawio.png) |
| API Flow | [`docs/images/api-flow.drawio.png`](./docs/images/api-flow.drawio.png) |
| Authentication Flow | [`docs/images/auth-flow.drawio.png`](./docs/images/auth-flow.drawio.png) |
| Feature Workflow | [`docs/images/feature-workflow.drawio.png`](./docs/images/feature-workflow.drawio.png) |
| Response Flow | [`docs/images/response-flow.drawio.png`](./docs/images/response-flow.drawio.png) |
| Threat Pipeline | [`docs/images/threat-pipeline.drawio.png`](./docs/images/threat-pipeline.drawio.png) |
| Editable Draw.io Files | [`docs/diagrams/`](./docs/diagrams/) |
| Evaluation Artifacts | [`evaluation/`](./evaluation/) |

## 📄 Responsible Use

CyberShield is intended for:

- defensive-security learning
- authorized security testing
- security engineering demonstrations
- portfolio and research use

Only run reconnaissance or scanning features against systems you own or have explicit authorization to test.

## 👩‍💻 Author

**Agrima Saxena**

Software Engineering · Applied AI · Cybersecurity

[LinkedIn](https://www.linkedin.com/in/agrima-saxena-142960426/) · [GitHub](https://github.com/agrima08s010315) · [Email](mailto:agrimalc@gmail.com)

**Live:** [CyberShield](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
