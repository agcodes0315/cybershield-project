# 🛡️ CyberShield
### AI-Assisted Security Operations Center (SOC) Platform for Critical Infrastructure

![React](https://img.shields.io/badge/React-20232A?style=flat&logo=react&logoColor=61DAFB)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat&logo=redis&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

CyberShield is a production-inspired SOC platform built to improve cyber resilience across Critical National Infrastructure (CNI) sectors — government, defence, healthcare, finance, transportation, and energy. It unifies threat intelligence, phishing detection, vulnerability prioritization, response orchestration, attack-graph analysis, and MITRE ATT&CK mapping into a single operational dashboard.

Built as a modular, cloud-ready platform, CyberShield demonstrates how modern SOC architectures can combine ML-assisted analysis, automation, and security analytics to centralize investigations, reduce repetitive analyst workflows, and improve operational visibility, while remaining approachable enough for learning, demonstration, and portfolio use.

---

### 🔗 Live Demo

| Service | URL |
|---|---|
| **Frontend** | [mango-pebble-099d8de00.7.azurestaticapps.net](https://mango-pebble-099d8de00.7.azurestaticapps.net) |
| **API Gateway** | [cybershield-api-gateway...azurecontainerapps.io](https://cybershield-api-gateway.niceforest-87cbfff3.centralindia.azurecontainerapps.io) |

---

## 📌 Table of Contents
- [Overview](#-overview)
- [Project Highlights](#project-highlights)
- [Problem Statement](#-problem-statement)
- [Key Features](#-key-features)
- [System Architecture](#️-system-architecture)
- [Low-Level Design](#-low-level-design)
- [Algorithm Engineering & Performance](#-algorithm-engineering--performance)
- [Technology Stack](#-technology-stack)
- [Implemented Modules](#-implemented-modules)
- [AI Capabilities](#-ai-capabilities)
- [Security Features](#-security-features)
- [Project Structure](#-project-structure)
- [API Endpoints](#-api-endpoints)
- [Local Installation](#-local-installation)
- [Environment Variables](#-environment-variables)
- [Azure Deployment](#-azure-deployment)
- [Testing](#-testing)
- [Known Limitations](#-known-limitations)
- [Roadmap](#-roadmap-planned--not-yet-implemented)
- [Author](#-author)

---

## 🌍 Overview

Modern organizations rely on multiple disconnected security tools for phishing detection, vulnerability assessment, malware analysis, email investigation, and incident response. This fragmented approach leads to alert fatigue, slow investigations, high Mean Time to Detect (MTTD), high Mean Time to Respond (MTTR), and manual security operations.

CyberShield unifies these capabilities into a centralized Security Operations Center, resembling enterprise products like Microsoft Sentinel, Splunk Enterprise, and CrowdStrike Falcon, purpose-built to be understandable, extensible, and demo-ready.

## Project Highlights

- Full-stack SOC platform using React, Express.js, FastAPI, PostgreSQL, and Redis
- Graph-based attack-path intelligence using BFS, DFS, and Dijkstra's algorithm
- MITRE ATT&CK mapping and security-event correlation
- ML-assisted phishing and URL threat analysis
- Human-governed SOAR response workflows and hash-chained audit logging
- Real-time WebSocket alerting
- Azure cloud deployment
- 140 automated unit and integration tests
- Reproducible before/after benchmark for the critical-asset discovery optimization (see [Algorithm Engineering](#-algorithm-engineering--performance))

| Component | Status |
|-----------|--------|
| Frontend | ✅ Live |
| API Gateway | ✅ Live |
| Detection Engine | ✅ Running |
| PostgreSQL | ✅ Connected |
| WebSockets | ✅ Enabled |

## 🎯 Problem Statement

Critical National Infrastructure (CNI) sectors face increasingly sophisticated cyber attacks, yet traditional security stacks rely on isolated products and signature-based detection.

CyberShield addresses this through ML-assisted threat intelligence, behaviour-driven security analytics, automated response orchestration, vulnerability prioritization, attack-graph analysis, cyber resilience assessment, and cloud-native SOC architecture.

## ✨ Key Features

**Security Operations** : SOC Command Center Dashboard, Real-time Security Monitoring, Threat Feed Dashboard, Analyst Workspace

**Threat Intelligence** : ML-Assisted URL Scanner, Email Header Analyzer, SPF/DKIM/DMARC Validation, Reconnaissance Engine, IP Reputation Analysis

**Attack Graph Intelligence** : Directed infrastructure graphs, minimum-hop BFS paths, lowest-cost Dijkstra paths, DFS blast-radius analysis, critical-asset discovery, containment simulation, and remediation prioritization

**Vulnerability Management** : Vulnerability Prioritization, Context-aware Risk Scoring, Patch Prioritization, Asset Criticality Ranking

**Malware Detection** : YARA Rule Engine, Malware Signature Analysis, IOC Detection

**Incident Response** : Human Approval Workflow, Response Orchestrator, Automated Playbooks, Audit Trail, Response Execution History

**Cyber Resilience** : End-to-End Resilience Analysis, Security Event Correlation, Organizational Risk Assessment

**Collaboration** : Community Threat Intelligence, Shared Security Reports, Analyst Collaboration

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    U[Security Analyst] --> F[React Frontend]

    F -->|REST API| G[Express API Gateway]
    F -->|WebSocket| W[Real-time Alert Fan-out]

    G --> AUTH[Authentication and RBAC]
    G --> P[(PostgreSQL)]
    G --> R[(Redis)]
    G --> D[FastAPI Detection Engine]

    D --> ML[ML URL Detection]
    D --> E[Email Analysis]
    D --> N[Recon and Network Analysis]
    D --> Y[YARA Rules]
    D --> T[Threat Feed Connectors]
    D --> AG[Attack Graph Engine]

    T --> PT[PhishTank]
    T --> VT[VirusTotal]
    T --> H[Have I Been Pwned]
    T --> S[Shodan]
    T --> AB[AbuseIPDB]

    R --> ORCH[SOAR Orchestrator]
    ORCH --> PB[Automated Playbook<br/>low-risk]
    ORCH --> APP[Human Approval Gate<br/>medium/high-risk]
    PB --> AUDIT[(Immutable Audit Log)]
    APP --> AUDIT
    AUDIT --> CR[Cyber Resilience Engine]

    G --> M[MITRE ATT&CK Mapping]
```

**Service boundaries:** the React dashboard communicates with backend services through the Express API gateway, which owns authentication, routing, and access control. PostgreSQL provides persistent application storage, while Redis supports low-latency application state and caching where configured.

**SOAR orchestrator placement:** low-risk findings (e.g., a URL scoring below the auto-remediation threshold) flow straight into the automated playbook path. Medium/high-risk findings are routed to the human approval gate before any playbook executes — the orchestrator never auto-executes anything above the configured risk threshold.

**Real-time fan-out:** the Express gateway maintains a WebSocket connection per active analyst session. New incidents, playbook completions, and approval requests are pushed to all connected clients rather than polled, so the SOC dashboard reflects new findings within the same detection cycle.

---

## 🔎 Low-Level Design

### Incident & audit trail schema

| Table | Key columns | Notes |
|---|---|---|
| `incidents` | `id`, `source_module`, `risk_score`, `status`, `created_at`, `updated_at` | Mutable while `status != closed`; `updated_at` tracks the state machine transition |
| `audit_log` | `id`, `incident_id`, `actor`, `action`, `payload_hash`, `prev_hash`, `timestamp` | **Append-only** — no `UPDATE`/`DELETE` grants at the DB role level. `prev_hash` chains each row to the previous entry's hash, so a tampered row breaks the chain and is detectable on verification |
| `users` | `id`, `email`, `password_hash`, `role_id` | Standard credential store, BCrypt-hashed |
| `roles` | `id`, `name`, `permission_bitmask` | See RBAC table below |

The hash-chained `audit_log` is what makes "immutable audit logging" a verifiable claim rather than a description — any row modified out-of-band fails the chain-verification check on next read.

### Incident state machine

```
detected → triaged → playbook_run → human_approved → closed
              │                            │
              └──────── rejected ──────────┘
                    (analyst declines the recommended action;
                     incident returns to triaged with a note)
```

Each transition is a row in `audit_log`, not just a status update, so the full lifecycle of every incident is reconstructable from the log alone, independent of the current `incidents.status` value.

### RBAC permission model

| Role | View incidents | Run automated playbook | Approve high-risk action | Manage users |
|---|:---:|:---:|:---:|:---:|
| Analyst | ✅ | ❌ | ❌ | ❌ |
| Senior Analyst | ✅ | ✅ (low-risk only) | ✅ | ❌ |
| SOC Lead | ✅ | ✅ | ✅ | ✅ |

Permissions are stored as a bitmask on `roles` and checked at the API gateway layer before a request reaches the FastAPI detection engine, so an unauthorized action is rejected before it consumes any detection-engine compute.

### Rate limiting

| Endpoint category | Threshold | Rationale |
|---|---|---|
| `/scan/url` | 30 req/min per analyst | Prevents accidental scan storms against a single suspicious domain |
| `/scan/email` | 20 req/min per analyst | Email parsing is more compute-heavy than URL scoring |
| `/orchestrator/execute` | 5 req/min per analyst | Playbook execution is the highest-consequence action in the system |
| `/auth/*` | 10 req/min per IP | Standard brute force mitigation |

---

## 🧮 Algorithm Engineering & Performance

CyberShield models infrastructure assets and trust relationships as a directed, weighted graph using adjacency lists, reverse adjacency lists, hash maps, and sets.

The attack-graph subsystem implements:

- **BFS** for minimum-hop attack paths
- **Dijkstra's algorithm** for lowest attacker-cost paths
- **DFS** for blast-radius and compromise-reachability analysis
- **Hash maps and sets** for constant-time-average asset and membership lookups
- **Priority queues / heaps** for remediation ranking
- **Adjacency lists** for memory-efficient graph representation

### Critical-Asset Discovery Optimization

The original implementation independently executed Dijkstra's algorithm for each critical asset. For `K` critical assets, the approximate complexity was:

```text
O(K × (V + E) log V)
```

The implementation was redesigned to perform a single-source shortest-path traversal combined with hash-set membership checks to identify the nearest critical asset instead. The optimized complexity is approximately:

```text
O((V + E) log V + K)
```

### Reproducible Benchmark

Both implementations were benchmarked back-to-back in a single execution (commit `bcdbba4` before, commit `d6770ea` after), on the same machine, Python environment, and deterministic synthetic graph generator.

| Metric | Before Optimization (`bcdbba4`) | After Optimization (`d6770ea`) |
|---|---:|---:|
| Graph nodes | 2,500 | 2,500 |
| Graph edges | 10,000 | 10,000 |
| Critical assets | 125 | 125 |
| Mean latency | 2434.16 ms | 0.84 ms |
| Median latency | 2461.10 ms | 0.83 ms |
| P95 latency | 2582.02 ms | 0.90 ms |

**Median critical-asset discovery latency dropped by approximately 99.97%, from ~2.46 s to ~0.83 ms.** Absolute timings vary by roughly 10–30% between benchmark sessions due to normal system-level factors (background load, cache state, interpreter startup); the reduction has been consistent across every independent run performed during development, and this table reflects the most complete paired session, run against the full test suite.

The optimized implementation was validated against the complete automated test suite:

```text
140 passed
```

Reproducibility artifacts are available under:

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

---

## 🛠 Technology Stack

| Layer | Stack |
|---|---|
| **Frontend** | React, Vite, Axios, Recharts, Lucide React, WebSockets, CSS3 |
| **API Gateway** | Node.js, Express, JWT Auth, Helmet, CORS, Rate Limiting, Morgan, WebSockets |
| **Detection Engine** | Python, FastAPI, scikit-learn (Random Forest + Gradient Boosting), YARA, Nmap, WHOIS |
| **Data Layer** | PostgreSQL, Redis |
| **Cloud** | Microsoft Azure — Static Web Apps, Container Apps, Docker |

## 📂 Implemented Modules

| Module | Description |
|---|---|
| SOC Dashboard | Centralized Security Operations Dashboard |
| URL Scanner | ML-assisted phishing URL detection |
| Email Analyzer | Email authentication and spoofing analysis |
| Reconnaissance | Domain intelligence and attack surface discovery |
| MITRE ATT&CK Mapping | Keyword-based technique/tactic mapping with coverage, confidence, and source aggregation |
| Attack Graph Intelligence | BFS/Dijkstra attack paths, DFS blast-radius analysis, critical-asset discovery, and containment simulation |
| Breach Checker | Credential exposure verification |
| Pen Testing | Controlled vulnerability assessment |
| YARA Scanner | Malware detection using YARA rules |
| GoPhish Simulator | Security awareness campaigns |
| Cyber Resilience | Organizational resilience analytics |
| Response Orchestrator | Automated response workflows |
| SOC Community | Threat intelligence collaboration |
| Settings | Workspace management |

## 🧠 AI Capabilities

Threat Intelligence Correlation • Context-aware Vulnerability Prioritization • Behaviour-based Risk Analysis • Incident Response Recommendation • Security Event Correlation • Email Spoofing Detection • Phishing URL Detection • Organizational Cyber Resilience Assessment

## 🔐 Security Features

JWT Authentication • Password Hashing • Input Sanitization • Role-based Access Control • Audit Logging • Human Approval Workflows • API Validation • Parameterised SQL Queries • Secure Azure Deployment

---

## 📁 Project Structure

```
CyberShield/
├── client/
│   ├── src/
│   │   ├── components/
│   │   ├── context/
│   │   ├── hooks/
│   │   ├── pages/
│   │   ├── services/
│   │   └── App.jsx
│   └── package.json
│
├── api-gateway/
│   ├── config/
│   ├── middleware/
│   ├── routes/
│   ├── utils/
│   ├── app.js
│   ├── server.js
│   └── package.json
│
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
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── scenarios/
│
├── evaluation/
│   ├── benchmark_graph_algorithms.py
│   ├── graph_algorithm_benchmark_before.csv
│   ├── graph_algorithm_benchmark_after.csv
│   └── graph_algorithm_verified_run.txt
│
├── docker-compose.yml
└── README.md
```

## 📡 API Endpoints

<details>
<summary><b>Authentication</b></summary>

```
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me
```
</details>

<details>
<summary><b>URL Scanning</b></summary>

```
POST /api/scan/url
GET  /api/scan/history
```
</details>

<details>
<summary><b>Email Analysis</b></summary>

```
POST /api/email/analyze
```
</details>

<details>
<summary><b>Threat Intelligence</b></summary>

```
POST /api/threats/fetch
GET  /api/threats/recent
GET  /api/threats/search
```
</details>

<details>
<summary><b>MITRE ATT&CK</b></summary>

```
GET /api/mitre
```
</details>

<details>
<summary><b>Reconnaissance</b></summary>

```
POST /api/recon/port-scan
POST /api/recon/abuse-check
POST /api/recon/full
```
</details>

<details>
<summary><b>Cyber Resilience</b></summary>

```
GET  /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents/:id/decide
POST /api/resilience/orchestrator/incidents/:id/auto-execute
GET  /api/resilience/audit/trail
GET  /api/resilience/audit/verify
```
</details>

FastAPI also auto-generates interactive docs at `/docs`, covering URL Analysis, Email Analysis, Reconnaissance, Vulnerability Prioritization, Response Orchestration, Audit, and Cyber Resilience.

---

## 🚀 Local Installation

### Prerequisites

- Node.js 20+
- Python 3.11+
- PostgreSQL
- Redis
- Git

### Clone the repository

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

# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```bash
cd client
npm install
npm run dev
```

Open **http://127.0.0.1:5173**

---

## 🔑 Environment Variables

**`api-gateway/.env`**
```env
NODE_ENV=development
PORT=5000
DATABASE_URL=postgresql://postgres:password@localhost:5432/cybershield
JWT_SECRET=replace_with_a_secure_secret
DETECTION_ENGINE_URL=http://127.0.0.1:8000
CORS_ORIGINS=http://localhost:5173
REDIS_URL=
```

**`client/.env`**
```env
VITE_API_BASE_URL=http://127.0.0.1:5000/api
VITE_WS_URL=ws://127.0.0.1:5000/ws
```

## ☁️ Azure Deployment

| Component | Target |
|---|---|
| Frontend | Azure Static Web Apps (build: `npm run build`, output: `dist`) |
| API Gateway | Azure Container App |
| Detection Engine | Azure Container App (separate service) |

**Production checks:**
```
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```
Also verify HTTPS, WSS WebSocket connectivity, CORS, authentication, database connectivity, detection-engine connectivity, and environment variables.

---

## 🧪 Testing

CyberShield includes automated unit and integration coverage across attack-graph analysis, event correlation, prediction, UEBA, incident response, audit integrity, and API workflows.

Latest verified run:

```text
140 passed
```

Coverage includes:

- BFS minimum-hop path discovery
- Dijkstra lowest-cost attack paths
- DFS blast-radius analysis
- Hash-map entity indexing
- Critical-asset discovery
- Remediation ranking
- MITRE ATT&CK mapping
- Event correlation
- UEBA anomaly detection
- Prediction workflows
- Response approvals and execution
- Hash-chain audit integrity
- Integration API workflows

### Manual deployment checklist

- [ ] User registration & login/logout
- [ ] Protected routes
- [ ] URL analysis & scan history
- [ ] Email analysis
- [ ] Reconnaissance
- [ ] Threat-feed refresh & IOC search
- [ ] MITRE mapping
- [ ] Response approvals & automated response
- [ ] Audit verification
- [ ] PDF report generation
- [ ] WebSocket alerts
- [ ] Admin operations & settings update
- [ ] Mobile layout

---

## ⚠️ Known Limitations

- MITRE mapping currently uses keyword-based classification, not a full ATT&CK Navigator integration
- Threat-feed diversity depends on configured provider API keys
- Some external integrations require paid or rate-limited API keys
- Network scanning may be restricted in managed cloud environments
- Production WebSocket behaviour depends on proxy and container configuration
- The Redis queue path has not yet been independently verified end-to-end; current wording describes it as supporting low-latency state/caching rather than asserting a specific queue architecture

---

## 🗺 Roadmap (planned — not yet implemented)

The items below are design targets, not shipped features. Each has a short blueprint so the design thinking is visible even before the code lands — none of this is represented as built.

| Enhancement | Design direction |
|---|---|
| **MITRE ATT&CK Navigator-style Heatmap** | The existing keyword-based mapping already surfaces coverage, technique, and tactic counts; this extends it into an interactive Navigator-style heatmap on the incident detail view, so an analyst sees *which stage of an attack chain* a finding belongs to at a glance, not just a raw score |
| **Behavioural Analytics Dashboard** | Baseline per-asset normal behaviour over a rolling window; flag deviations as anomaly scores feeding the existing risk-scoring pipeline |
| **SIEM Integration** | Expose a normalized event stream (CEF/JSON over Syslog) from the `audit_log` table so CyberShield can sit alongside Splunk/Sentinel as a source |
| **Threat Actor Attribution** | Correlate IOC patterns against open threat-intel feeds to suggest — not assert — likely actor clusters, as a confidence-scored hint |
| **Kubernetes Deployment** | Migrate the detection engine and gateway to AKS with autoscaling keyed on Redis queue depth |
| **Attack-Graph Persistence & Historical Analysis** | Persist graph snapshots and attack-path changes over time to support historical investigation and trend analysis |
| **AI Security Copilot** | LLM-backed assistant scoped to read-only queries against the incident/audit schema, restricted to the same RBAC model as human analysts |
| **Real-time Streaming Analytics** | Replace Redis-as-queue with Kafka/Azure Event Hubs once incident volume exceeds single-instance buffering |

---

## 📄 Disclaimer

CyberShield is intended for educational, authorised defensive-security, and portfolio use only. Run reconnaissance or scanning features only against systems you own or have explicit permission to test.

## 👩‍💻 Author

**Agrima Saxena**
🔗 [LinkedIn](https://www.linkedin.com/in/agrima-saxena-142960426/) · 💻 [GitHub](https://github.com/agrima08s010315)

---

⭐ **If you found this project interesting, consider giving it a star**
