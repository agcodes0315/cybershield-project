# CyberShield

### AI-Assisted Security Operations Center for Critical Infrastructure

CyberShield is a full-stack security operations platform that brings threat detection, attack-path analysis, vulnerability prioritization, threat intelligence, incident response, and analyst-controlled remediation into one workflow.

The project was built to explore a broader engineering question:

**How can security signals move from detection to an explainable, auditable response without giving automated systems unrestricted control over high-impact decisions?**

CyberShield combines a React frontend, Node.js API gateway, FastAPI detection services, PostgreSQL, Redis, WebSockets, graph algorithms, machine learning workflows, and Microsoft Azure deployment.

[Live Demo](https://mango-pebble-099d8de00.7.azurestaticapps.net/) · [System Design](./docs/SYSTEM_DESIGN.md) · [Architecture Diagrams](./docs/diagrams/)

---

## Overview

Security analysts often move between separate tools for phishing analysis, threat intelligence, vulnerability management, network reconnaissance, attack-path analysis, and incident response.

CyberShield connects these workflows in one SOC-style platform.

An analyst can:

* inspect suspicious URLs, domains, IP addresses, and email headers
* investigate external threat intelligence
* analyze possible attack paths through infrastructure
* identify critical assets and compromise reachability
* map findings to MITRE ATT&CK
* prioritize vulnerabilities using security context
* inspect YARA and IOC matches
* receive real-time security updates through WebSockets
* review recommended response actions
* approve higher-risk remediation manually
* reconstruct incident activity through an auditable history

CyberShield is not intended to reproduce every feature of a commercial SIEM or SOAR platform. It focuses on the architecture and engineering decisions involved in connecting detection, analysis, prioritization, and controlled response.

---

## Engineering Highlights

| Area                               |                                 Result |
| ---------------------------------- | -------------------------------------: |
| Graph benchmark                    |              2,500 nodes, 10,000 edges |
| Critical assets evaluated          |                                    125 |
| Median latency before optimization |                             2461.10 ms |
| Median latency after optimization  |                                0.83 ms |
| Median latency reduction           |                   approximately 99.97% |
| Automated tests                    |                            140 passing |
| Real-time communication            |                             WebSockets |
| Cloud deployment                   |                        Microsoft Azure |
| Response model                     | Human approval for higher-risk actions |

The performance figures above come from committed benchmark artifacts rather than estimated measurements.

---

## Architecture

CyberShield uses separate frontend, gateway, analysis, state, and persistence layers.

The React application communicates with an Express API gateway. The gateway provides authentication, authorization, validation, rate limiting, and routing.

Security analysis workloads are handled by a stateless FastAPI detection engine.

PostgreSQL is used for persistent application data. Redis supports low-latency state and caching where configured. WebSockets deliver security updates to connected analyst sessions.

<p>
  <img src="./docs/images/hld.drawio.png"
       alt="CyberShield high-level architecture"
       width="92%">
</p>

### Request Flow

```text
React Client
    |
    v
Express API Gateway
    |
    +--> Authentication
    +--> RBAC
    +--> Validation
    +--> Rate Limiting
    |
    +-----------> PostgreSQL
    |
    +-----------> FastAPI Detection Engine
                        |
                        +--> Threat Intelligence
                        +--> Email Analysis
                        +--> Attack Graph
                        +--> Reconnaissance
                        +--> Security Analytics
```

The detection engine is kept separate from the public authentication surface. Client requests pass through the gateway before protected workflows can reach downstream services.

---

## Threat Processing

A security finding moves through several stages before a response is executed.

```text
Security Input
    |
    v
API Gateway
    |
    v
Authentication and RBAC
    |
    v
Detection and Analysis
    |
    +--> Threat Intelligence
    +--> Attack Graph
    +--> MITRE ATT&CK
    +--> Vulnerability Context
    |
    v
Risk Evaluation
    |
    v
Response Recommendation
    |
    +--> Low Risk --> Automated Playbook
    |
    +--> Higher Risk --> Human Approval
                            |
                            v
                       Response Action
                            |
                            v
                        Audit Trail
```

The platform deliberately separates **recommendation** from **authorization** for higher-risk actions.

---

## Core Capabilities

### Threat Intelligence

CyberShield combines several signals during investigation:

* suspicious URL analysis
* IP reputation
* domain intelligence
* WHOIS inspection
* SSL information
* IOC search
* external threat-feed integrations
* phishing indicators

### Email Security

The email-analysis workflow supports:

* email-header inspection
* SPF validation
* DKIM checks
* DMARC checks
* sender-domain analysis
* spoofing indicators

### Attack Graph Analysis

Infrastructure relationships are represented as a directed weighted graph.

The subsystem supports:

* BFS minimum-hop paths
* Dijkstra lowest-cost paths
* DFS blast-radius analysis
* critical-asset discovery
* compromise reachability
* remediation prioritization
* containment simulation

### Incident Response

Response workflows distinguish between low-risk automation and actions requiring analyst approval.

The system includes:

* automated low-risk playbooks
* analyst approval workflows
* incident-state transitions
* remediation history
* response orchestration
* audit logging

### Malware Analysis

CyberShield supports:

* YARA rules
* IOC detection
* signature-based analysis

### MITRE ATT&CK

Security findings can be mapped to MITRE ATT&CK techniques and tactics to provide additional context during investigation.

---

## Graph Algorithm Optimization

One of the main performance improvements in CyberShield was made in the critical-asset discovery workflow.

### Initial Implementation

The original implementation ran Dijkstra's algorithm independently for each critical asset.

For `K` critical assets:

```text
O(K × (V + E) log V)
```

The approach was correct, but repeated shortest-path computation became expensive as the number of critical assets increased.

### Optimized Implementation

The workflow was redesigned to perform one single-source shortest-path traversal and use hash-set membership checks while evaluating critical assets.

Approximate complexity:

```text
O((V + E) log V + K)
```

### Benchmark

Both implementations were evaluated on the same deterministic synthetic graph.

| Metric          |     Before |   After |
| --------------- | ---------: | ------: |
| Nodes           |      2,500 |   2,500 |
| Edges           |     10,000 |  10,000 |
| Critical assets |        125 |     125 |
| Mean latency    | 2434.16 ms | 0.84 ms |
| Median latency  | 2461.10 ms | 0.83 ms |
| P95 latency     | 2582.02 ms | 0.90 ms |

The recorded benchmark reduced median critical-asset discovery latency from approximately **2.46 seconds to 0.83 milliseconds**, an approximate **99.97% reduction**.

The optimized implementation was also validated against the complete automated test suite:

```text
140 passed
```

Benchmark artifacts are available in:

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

---

## Authentication and Authorization

CyberShield uses JWT-based authentication with role-based access control.

| Role           | View Incidents | Run Playbook | Approve Higher-Risk Action | Manage Users |
| -------------- | :------------: | :----------: | :------------------------: | :----------: |
| Analyst        |       Yes      |      No      |             No             |      No      |
| Senior Analyst |       Yes      |   Low risk   |             Yes            |      No      |
| SOC Lead       |       Yes      |      Yes     |             Yes            |      Yes     |

Authorization is enforced by the API gateway before protected actions reach downstream services.

Additional controls include:

* BCrypt password hashing
* request validation
* rate limiting
* Helmet security headers
* CORS restrictions
* parameterized SQL queries
* human approval for higher-risk actions

---

## Auditable Incident Lifecycle

CyberShield records meaningful incident transitions instead of keeping only the latest state.

```text
detected
   |
   v
triaged
   |
   v
playbook_run
   |
   +--> rejected --> triaged
   |
   v
human_approved
   |
   v
closed
```

Audit records can include:

```text
incident_id
actor
action
payload_hash
previous_hash
timestamp
```

Records are hash-chained using the previous entry's hash.

This provides a way to detect unexpected changes to historical audit records and reconstruct important actions independently of an incident's current status.

---

## Real-Time Updates

WebSockets are used to push operational updates to connected analyst sessions.

Examples include:

* newly created incidents
* approval requests
* completed playbooks
* threat-analysis results
* response-state changes

This reduces reliance on continuous client polling.

---

## AI and Security Analytics

Machine learning and analytics are used as decision-support mechanisms rather than unrestricted decision authorities.

| Capability                   | Purpose                              |
| ---------------------------- | ------------------------------------ |
| URL analysis                 | classify suspicious URLs             |
| Phishing detection           | identify phishing indicators         |
| Vulnerability prioritization | rank findings using security context |
| Event correlation            | connect related security events      |
| Behaviour analysis           | identify unusual activity            |
| Incident recommendation      | suggest response direction           |
| Resilience scoring           | summarize security posture           |

Higher-risk remediation remains analyst controlled.

---

## Technology Stack

| Layer                   | Technology                                 |
| ----------------------- | ------------------------------------------ |
| Frontend                | React, Vite, Axios, Recharts, Lucide React |
| API Gateway             | Node.js, Express.js                        |
| Detection Engine        | Python, FastAPI                            |
| Machine Learning        | scikit-learn                               |
| Graph Analysis          | BFS, DFS, Dijkstra                         |
| Malware Analysis        | YARA                                       |
| Reconnaissance          | Nmap, WHOIS                                |
| Database                | PostgreSQL                                 |
| Cache and State         | Redis                                      |
| Real-Time Communication | WebSockets                                 |
| Authentication          | JWT, BCrypt                                |
| Cloud                   | Microsoft Azure                            |
| Containers              | Docker                                     |
| Testing                 | pytest                                     |

---

## Implemented Modules

| Module                   | Purpose                                       |
| ------------------------ | --------------------------------------------- |
| SOC Dashboard            | operational security overview                 |
| URL Scanner              | suspicious URL analysis                       |
| Email Analyzer           | email authentication and spoofing analysis    |
| Reconnaissance           | domain and network intelligence               |
| Threat Intelligence      | IOC and reputation analysis                   |
| MITRE ATT&CK             | technique and tactic mapping                  |
| Attack Graph             | path, reachability, and blast-radius analysis |
| Vulnerability Management | prioritization and risk scoring               |
| Breach Checker           | credential exposure verification              |
| YARA Scanner             | malware rule matching                         |
| GoPhish Simulator        | awareness workflows                           |
| Response Orchestrator    | incident-response coordination                |
| Audit Engine             | action and state history                      |
| Cyber Resilience         | security-posture analytics                    |
| SOC Community            | shared threat intelligence                    |
| Settings                 | workspace configuration                       |

---

## API Surface

### Authentication

```http
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me
```

### URL Analysis

```http
POST /api/scan/url
GET  /api/scan/history
```

### Email Analysis

```http
POST /api/email/analyze
```

### Threat Intelligence

```http
POST /api/threats/fetch
GET  /api/threats/recent
GET  /api/threats/search
```

### MITRE ATT&CK

```http
GET /api/mitre
```

### Reconnaissance

```http
POST /api/recon/port-scan
POST /api/recon/abuse-check
POST /api/recon/full
```

### Incident Response

```http
GET  /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents/:id/decide
POST /api/resilience/orchestrator/incidents/:id/auto-execute

GET  /api/resilience/audit/trail
GET  /api/resilience/audit/verify
```

FastAPI exposes interactive OpenAPI documentation at:

```text
/docs
```

---

## Repository Structure

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

---

## Running CyberShield Locally

### 1. Clone the repository

```bash
git clone https://github.com/agcodes0315/cybershield-project.git
cd cybershield-project
```

### 2. Start the API gateway

```bash
cd api-gateway
npm install
npm run dev
```

### 3. Start the detection engine

```bash
cd detection-engine
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Start FastAPI:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 4. Start the frontend

```bash
cd client
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

---

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

Production credentials, secrets, and provider API keys should not be committed to the repository.

---

## Azure Deployment

| Component        | Deployment            |
| ---------------- | --------------------- |
| Frontend         | Azure Static Web Apps |
| API Gateway      | Azure Container Apps  |
| Detection Engine | Azure Container Apps  |
| Containers       | Docker                |

Deployment checks include:

```http
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```

Production validation also covers HTTPS, WSS connectivity, CORS, authentication, PostgreSQL connectivity, detection-engine connectivity, and environment configuration.

---

## Testing

CyberShield includes automated testing across graph analysis, incident workflows, security analytics, API behaviour, and audit integrity.

Latest verified run:

```text
140 passed
```

Coverage includes:

* BFS minimum-hop paths
* Dijkstra weighted attack paths
* DFS blast-radius analysis
* graph indexing
* critical-asset discovery
* remediation ranking
* MITRE ATT&CK mapping
* event correlation
* UEBA workflows
* prediction workflows
* response approvals
* response execution
* audit-chain integrity
* API integration workflows

---

## Reproducibility

Performance benchmark artifacts are committed under `evaluation/`.

The repository includes the benchmark implementation, recorded before-and-after results, raw CSV output, and the verified run used for the performance figures presented in this README.

---

## Current Limitations

CyberShield is a defensive-security engineering project rather than a production replacement for Microsoft Sentinel, Splunk, CrowdStrike, or a commercial SOAR platform.

Current limitations include:

* MITRE mapping uses keyword-oriented classification
* threat-feed coverage depends on configured external providers
* external intelligence providers may enforce rate limits
* cloud environments may restrict network scanning
* WebSocket behaviour depends on proxy and container configuration
* Redis is used for low-latency state and caching where configured
* distributed queue behaviour has not been independently benchmarked end-to-end

Documenting these limitations is intentional. They define where the current implementation ends and where further engineering work would begin.

---

## Future Work

Areas that can extend the platform include:

| Area                     | Direction                                      |
| ------------------------ | ---------------------------------------------- |
| ATT&CK Visualization     | interactive ATT&CK coverage                    |
| Behaviour Analytics      | rolling asset baselines and anomaly scoring    |
| SIEM Integration         | normalized event export for Sentinel or Splunk |
| Threat Actor Context     | confidence-scored IOC correlation              |
| Historical Attack Graphs | graph snapshots and path evolution             |
| Security Assistant       | read-only, RBAC-constrained analyst assistance |
| Kubernetes               | AKS-based service orchestration                |
| Streaming Analytics      | Event Hubs or Kafka for larger event volumes   |

---

## Documentation

| Resource                    | Location                                                                               |
| --------------------------- | -------------------------------------------------------------------------------------- |
| High-Level Architecture     | [`docs/images/hld.drawio.png`](./docs/images/hld.drawio.png)                           |
| API Flow                    | [`docs/images/api-flow.drawio.png`](./docs/images/api-flow.drawio.png)                 |
| Authentication Flow         | [`docs/images/auth-flow.drawio.png`](./docs/images/auth-flow.drawio.png)               |
| Entity Relationship Diagram | [`docs/images/ER_Diagram_Clean.drawio.png`](./docs/images/ER_Diagram_Clean.drawio.png) |
| Feature Workflow            | [`docs/images/feature-workflow.drawio.png`](./docs/images/feature-workflow.drawio.png) |
| Response Flow               | [`docs/images/response-flow.drawio.png`](./docs/images/response-flow.drawio.png)       |
| Threat Pipeline             | [`docs/images/threat-pipeline.drawio.png`](./docs/images/threat-pipeline.drawio.png)   |
| Editable Diagrams           | [`docs/diagrams/`](./docs/diagrams/)                                                   |
| System Design               | [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md)                                     |
| Evaluation Artifacts        | [`evaluation/`](./evaluation/)                                                         |

---

## Responsible Use

CyberShield is intended for defensive security, authorized testing, security-engineering demonstrations, learning, and research.

Reconnaissance, scanning, or security-testing functionality should only be used against systems you own or have explicit permission to assess.

---

## Author

### Agrima Saxena

Software Engineering · Applied AI · Cybersecurity

[GitHub](https://github.com/agcodes0315) · [LinkedIn](https://www.linkedin.com/in/agrima-saxena-142960426/) · [Live Demo](https://mango-pebble-099d8de00.7.azurestaticapps.net/)

**Repository:** [github.com/agcodes0315/cybershield-project](https://github.com/agcodes0315/cybershield-project)
