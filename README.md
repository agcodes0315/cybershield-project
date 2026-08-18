# CyberShield

### AI-Assisted Security Operations Center for Threat Detection, Investigation and Human-Governed Response

**CyberShield is a full-stack Security Operations Center platform that connects threat intelligence, phishing analysis, reconnaissance, MITRE ATT&CK mapping, attack-path analysis and incident response in one analyst workspace.**

[![Live Demo](https://img.shields.io/badge/Live_Demo-Open_CyberShield-0078D4?style=for-the-badge\&logo=microsoftazure\&logoColor=white)](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
[![System Design](https://img.shields.io/badge/System_Design-Architecture-2563EB?style=for-the-badge)](./docs/SYSTEM_DESIGN.md)
[![Tests](https://img.shields.io/badge/Tests-140_Passing-16A34A?style=for-the-badge\&logo=pytest\&logoColor=white)](#testing)

<img src="./docs/images/1.jpeg"
  alt="CyberShield SOC Command Center"
  width="100%"/>

CyberShield was designed around a simple principle:

> **Detection should be fast. Response should be explainable. High-impact decisions should remain under human control.**

---

## What CyberShield Does

Security investigations rarely happen inside one tool.

An analyst may need to inspect a suspicious email, investigate an IP address, check external threat intelligence, understand the associated ATT&CK technique, determine which systems are exposed, and decide whether a response can safely be automated.

CyberShield connects those steps into one workflow.

An analyst can:

* inspect suspicious emails and authentication headers
* investigate domains, IP addresses and infrastructure
* aggregate external threat intelligence
* map findings to MITRE ATT&CK
* analyze attack paths and critical assets
* prioritize remediation
* monitor incidents in real time
* execute low-risk response playbooks
* require human approval for higher-impact actions
* verify incident history using a hash-chained audit trail

The goal is not to reproduce every feature of a commercial SIEM.

The goal is to demonstrate how the major engineering pieces of a modern security operations platform can work together as one understandable system.

---

## SOC Command Center

The command center provides a single operational view of the environment.

It brings together platform health, threat intelligence, MITRE coverage, incidents, detection activity and response status.

<img src="./docs/images/1.jpeg"
  alt="CyberShield SOC Command Center overview"
  width="100%"/>

The dashboard is updated using backend APIs and WebSocket events so analysts do not have to rely only on repeated polling.

Key operational signals include:

* threat records
* critical threats
* MITRE coverage
* active incidents
* response actions
* platform health
* threat activity
* detection status

---

## Cyber Resilience

Security findings are more useful when they are connected to organizational impact.

The Cyber Resilience workspace evaluates risk, remediation priorities, incidents, containment status and audit integrity.

<img src="./docs/images/2.jpeg"
  alt="CyberShield Cyber Resilience workspace"
  width="100%"/>

This layer helps answer questions such as:

* Which findings deserve attention first?
* Which critical assets are exposed?
* What is the current organizational risk?
* Have previous response actions preserved audit integrity?
* Which incidents are still waiting for action?

---

## Human-Governed Incident Response

CyberShield contains a SOAR-style response orchestrator for coordinating security actions.

<img src="./docs/images/3.jpeg"
  alt="CyberShield Response Orchestrator"
  width="100%"/>

The system distinguishes between low-risk actions that can be executed automatically and higher-risk actions that require analyst approval.

```text
Threat Detected
      |
      v
Risk Evaluation
      |
      +------ Low Risk ------> Automated Playbook
      |
      +------ Higher Risk ---> Human Approval
                                  |
                                  v
                             Response Action
                                  |
                                  v
                              Audit Trail
```

This prevents the recommendation engine from silently becoming the final decision-maker.

---

## Email Threat Analysis

CyberShield includes an investigation workflow for suspicious email headers.

The analyzer inspects sender identity, routing information, authentication results and phishing indicators.

<img src="./docs/images/4.1.jpeg"
  alt="CyberShield Email Analyzer input workflow"
  width="100%"/>

Checks include:

* SPF
* DKIM
* DMARC
* Return-Path consistency
* Reply-To mismatch
* routing hops
* suspicious URLs
* sender impersonation indicators
* content signals

The result is presented as an analyst-readable verdict instead of only returning a raw numerical score.

<img src="./docs/images/4.jpeg"
  alt="CyberShield phishing and email spoofing analysis result"
  width="100%"/>

The investigation view separates header parsing, authentication, content analysis and final threat evaluation so an analyst can understand how the verdict was produced.

---

## Reconnaissance

The reconnaissance workspace gathers authorized domain, DNS, IP and network intelligence.

<img src="./docs/images/5.jpeg"
  alt="CyberShield reconnaissance workspace"
  width="100%"/>

The workflow can combine:

* domain resolution
* IP information
* exposed ports
* infrastructure signals
* abuse reputation
* WHOIS information
* network observations

Reconnaissance is intended only for systems that the operator owns or has explicit permission to assess.

---

## Threat Intelligence Center

CyberShield aggregates threat information from external providers into a common investigation layer.

<img src="./docs/images/6.jpeg"
  alt="CyberShield Threat Intelligence Center"
  width="100%"/>

Supported or designed integrations include:

* PhishTank
* VirusTotal
* AbuseIPDB
* Shodan
* Have I Been Pwned

External intelligence is treated as evidence rather than absolute truth.

Provider failures, conflicting results or rate limits should not silently determine the final application decision.

---

## MITRE ATT&CK Intelligence

Threat records can be mapped to MITRE ATT&CK tactics and techniques.

<img src="./docs/images/7.jpeg"
  alt="CyberShield MITRE ATT&CK explorer"
  width="100%"/>

The ATT&CK workspace helps analysts move from a raw IOC toward an understanding of adversary behavior.

It supports:

* tactic filtering
* technique search
* IOC search
* severity filtering
* technique-level investigation
* ATT&CK coverage visibility

Current mapping is intentionally documented as keyword-oriented rather than presented as a production-grade ATT&CK inference engine.

---

## Privacy-Aware Breach Checking

CyberShield also includes credential exposure checks using the Have I Been Pwned k-anonymity model.

<img src="./docs/images/8.jpeg"
  alt="CyberShield Breach Checker"
  width="100%"/>

For password checks, the full password is not sent to the breach service.

Only the first five characters of the SHA-1 hash are used for the remote lookup, while comparison of the returned suffixes can be completed locally.

The interface also separates breach exposure from password-strength analysis because these represent different security questions.

---

## Engineering Highlights

| Area                               |                                 Result |
| ---------------------------------- | -------------------------------------: |
| Attack graph benchmark             |                            2,500 nodes |
| Graph edges                        |                                 10,000 |
| Critical assets                    |                                    125 |
| Median latency before optimization |                             2461.10 ms |
| Median latency after optimization  |                                0.83 ms |
| Median latency reduction           |               approximately **99.97%** |
| Automated tests                    |                        **140 passing** |
| Real-time communication            |                             WebSockets |
| Response model                     | Human approval for higher-risk actions |
| Cloud platform                     |                        Microsoft Azure |

The performance results above come from committed deterministic benchmark artifacts rather than estimated measurements.

---

# System Architecture

CyberShield separates the user interface, gateway, detection engine and persistent state into independently deployable components.

<img src="./docs/images/9.jpeg"
  alt="CyberShield service architecture"
  width="100%"/>

The core runtime path is:

```text
React Frontend
      |
      v
Express API Gateway
      |
      +------ PostgreSQL
      |
      +------ Redis
      |
      v
FastAPI Detection Engine
      |
      +------ URL Analysis
      +------ Email Analysis
      +------ Reconnaissance
      +------ Threat Intelligence
      +------ MITRE Mapping
      +------ Attack Graph Analysis
      |
      v
Response Orchestrator
      |
      +------ Automated Playbook
      |
      +------ Human Approval
      |
      v
Audit + Cyber Resilience
```

### Why separate services?

The React frontend, Express gateway and FastAPI detection engine have different responsibilities.

Separating them allows each layer to be developed, deployed and scaled independently.

The API gateway remains the primary trust boundary for:

* authentication
* authorization
* request validation
* rate limiting
* routing
* WebSocket coordination

The detection engine remains focused on security analysis.

---

## High-Level Design

<img src="./docs/images/hld.drawio.png"
  alt="CyberShield High-Level Design"
  width="100%"/>

At a high level, CyberShield consists of:

| Component                | Responsibility                               |
| ------------------------ | -------------------------------------------- |
| React Frontend           | Analyst workspace and SOC interface          |
| Express API Gateway      | Authentication, RBAC, validation and routing |
| FastAPI Detection Engine | Security analysis and detection workflows    |
| PostgreSQL               | Persistent application and audit data        |
| Redis                    | Low-latency state and caching                |
| SOAR Orchestrator        | Response coordination                        |
| WebSockets               | Real-time analyst updates                    |
| External Providers       | Threat-intelligence enrichment               |

---

## Request and API Flow

Every protected request enters through the Express gateway.

<img src="./docs/images/api-flow.drawio.png"
  alt="CyberShield API request flow"
  width="100%"/>

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
Helmet + CORS + JWT + RBAC + Rate Limiting
      |
      v
Route Decision
     / \
    /   \
 CRUD   Analysis
  |        |
  v        v
Postgres  FastAPI
     \     /
      Result
        |
        v
Persist / Cache
        |
        +----> WebSocket Event
        |
        v
HTTP Response
```

---

## Authentication and RBAC

Authentication is based on JWTs with role-aware authorization.

<img src="./docs/images/auth-flow.drawio.png"
  alt="CyberShield authentication and RBAC flow"
  width="100%"/>

The authorization model currently defines three roles.

| Role           | View Incidents | Run Playbook | Approve Higher-Risk Actions | Manage Users |
| -------------- | :------------: | :----------: | :-------------------------: | :----------: |
| Analyst        |       Yes      |      No      |              No             |      No      |
| Senior Analyst |       Yes      |   Low risk   |             Yes             |      No      |
| SOC Lead       |       Yes      |      Yes     |             Yes             |      Yes     |

Protected actions are checked before reaching downstream services.

Security controls include:

* JWT authentication
* BCrypt password hashing
* role-based authorization
* request validation
* rate limiting
* Helmet headers
* CORS restrictions
* parameterized SQL queries

---

## Threat Detection Pipeline

URL and email investigations share a common detection pipeline.

<img src="./docs/images/threat-pipeline.drawio.png"
  alt="CyberShield threat detection pipeline"
  width="100%"/>

A typical analysis follows this path:

```text
URL / Email
     |
     v
Redis Lookup
     |
     v
Feature Extraction
     |
     v
Threat Intelligence Enrichment
     |
     v
ML Risk Model
     |
     v
Context-Aware Risk Score
     |
     v
MITRE ATT&CK Mapping
     |
     v
Persist Result
     |
     v
WebSocket Update
```

---

## Attack Graph Engineering

CyberShield represents infrastructure relationships using a directed weighted graph.

The graph subsystem supports:

* BFS minimum-hop paths
* Dijkstra lowest-cost attack paths
* DFS blast-radius analysis
* critical-asset discovery
* compromise reachability
* containment simulation
* remediation prioritization

One of the main engineering improvements in the project was optimizing critical-asset discovery.

### Initial approach

The first implementation ran Dijkstra independently for every critical asset.

For `K` critical assets:

```text
O(K × (V + E) log V)
```

This produced correct results but repeated the same expensive graph traversal many times.

### Optimized approach

The implementation was redesigned around a single-source shortest-path traversal followed by constant-time hash-set membership checks.

Approximate complexity:

```text
O((V + E) log V + K)
```

### Benchmark

The before and after implementations were evaluated using the same deterministic synthetic graph.

| Metric          |     Before |   After |
| --------------- | ---------: | ------: |
| Nodes           |      2,500 |   2,500 |
| Edges           |     10,000 |  10,000 |
| Critical assets |        125 |     125 |
| Mean latency    | 2434.16 ms | 0.84 ms |
| Median latency  | 2461.10 ms | 0.83 ms |
| P95 latency     | 2582.02 ms | 0.90 ms |

Median latency decreased from approximately **2.46 seconds to 0.83 milliseconds** in the recorded benchmark.

That represents an approximate **99.97% reduction in median critical-asset discovery latency**.

The optimized implementation was also validated against the complete test suite:

```text
140 passed
```

Benchmark artifacts are available under:

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

---

## Incident Response Flow

The response lifecycle keeps recommendation, approval, execution and auditing separate.

<img src="./docs/images/response-flow.drawio.png"
  alt="CyberShield incident response flow"
  width="100%"/>

Important state transitions are written to the audit trail.

This makes it possible to reconstruct what happened even after the current incident state changes.

---

## End-to-End Analyst Workflow

<img src="./docs/images/feature-workflow.drawio.png"
  alt="CyberShield analyst feature workflow"
  width="100%"/>

A typical investigation can move through:

```text
Login
  |
  v
SOC Command Center
  |
  v
URL / Email / IOC Analysis
  |
  v
Threat Intelligence
  |
  v
Reconnaissance
  |
  v
MITRE ATT&CK Mapping
  |
  v
Unified Risk Assessment
  |
  v
Response Orchestrator
  |
  +--> Automated Playbook
  |
  +--> Human Approval
  |
  v
Cyber Resilience
  |
  v
Audit and Investigation
```

WebSocket events operate alongside this workflow and update connected analysts when important security events occur.

---

## Database Design

<img src="./docs/images/ER_Diagram_Clean.drawio.png"
  alt="CyberShield Entity Relationship Diagram"
  width="100%"/>

The persistent model centers around:

* `roles`
* `users`
* `threat_entries`
* `incidents`
* `responses`
* `audit_log`

Important relationships include:

```text
roles            1 -> N users
users            1 -> N threat_entries
users            1 -> N incidents
users            1 -> N responses
threat_entries   1 -> 0..1 incidents
incidents        1 -> N audit_log
incidents        1 -> N responses
```

The audit log is append-oriented and hash chained.

---

## Tamper-Evident Audit Trail

Important automated and human actions are written to an audit chain.

Each entry can include:

```text
incident_id
actor
action
payload_hash
prev_hash
timestamp
```

Conceptually:

```text
Previous Hash
     +
Event Payload
     +
Actor
     +
Action
     +
Timestamp
     |
     v
Current Hash
```

Changing historical data changes the derived hash and breaks chain verification.

This does not make the database immutable, but it provides a mechanism for detecting unexpected modification of historical audit records.

---

## Deployment Architecture

CyberShield is designed so the frontend and backend services can be deployed independently.

<img src="./docs/images/deployment_architecture.drawio.png"
  alt="CyberShield Azure deployment architecture"
  width="100%"/>

| Component                 | Deployment            |
| ------------------------- | --------------------- |
| Frontend                  | Azure Static Web Apps |
| API Gateway               | Azure Container Apps  |
| Detection Engine          | Azure Container Apps  |
| Persistent Data           | PostgreSQL            |
| Cache / Operational State | Redis                 |
| Containerization          | Docker                |

The browser communicates with the frontend and API gateway over HTTPS and WSS.

Persistent infrastructure remains behind the application layer rather than being exposed directly to the public client.

---

## Technology Stack

| Layer                   | Technology                                 |
| ----------------------- | ------------------------------------------ |
| Frontend                | React, Vite, Axios, Recharts, Lucide React |
| API Gateway             | Node.js, Express                           |
| Detection Engine        | Python, FastAPI                            |
| Machine Learning        | scikit-learn                               |
| Graph Analysis          | BFS, DFS, Dijkstra                         |
| Malware Analysis        | YARA                                       |
| Reconnaissance          | Nmap, WHOIS                                |
| Database                | PostgreSQL                                 |
| Cache                   | Redis                                      |
| Real-Time Communication | WebSockets                                 |
| Authentication          | JWT, BCrypt                                |
| Cloud                   | Microsoft Azure                            |
| Containers              | Docker                                     |
| Testing                 | pytest                                     |

---

## Implemented Modules

| Module                   | Purpose                                      |
| ------------------------ | -------------------------------------------- |
| SOC Command Center       | Unified security operations overview         |
| Cyber Resilience         | Organizational risk and remediation analysis |
| Response Orchestrator    | Human-governed incident response             |
| Email Analyzer           | Authentication and phishing analysis         |
| Reconnaissance           | Domain and network intelligence              |
| Threat Intelligence      | IOC and reputation investigation             |
| MITRE ATT&CK             | Tactic and technique mapping                 |
| Breach Checker           | Credential exposure analysis                 |
| Attack Graph             | Attack paths and blast-radius analysis       |
| Vulnerability Management | Risk-based prioritization                    |
| YARA Scanner             | Malware rule matching                        |
| GoPhish Simulator        | Security-awareness workflows                 |
| Audit Engine             | Incident action history                      |
| Settings                 | Workspace configuration                      |

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

FastAPI also exposes interactive OpenAPI documentation at:

```text
/docs
```

---

## Repository Structure

```text
cybershield-project/
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
│   ├── models/
│   └── rules/
|
├── docs/
│   ├── diagrams/
│   ├── images/
│   │   ├── 1.jpeg
│   │   ├── 2.jpeg
│   │   ├── 3.jpeg
│   │   ├── 4.jpeg
│   │   ├── 4.1.jpeg
│   │   ├── 5.jpeg
│   │   ├── 6.jpeg
│   │   ├── 7.jpeg
│   │   ├── 8.jpeg
│   │   ├── 9.jpeg
│   │   ├── hld.drawio.png
│   │   ├── api-flow.drawio.png
│   │   ├── auth-flow.drawio.png
│   │   ├── response-flow.drawio.png
│   │   ├── threat-pipeline.drawio.png
│   │   ├── feature-workflow.drawio.png
│   │   ├── deployment_architecture.drawio.png
│   │   └── ER_Diagram_Clean.drawio.png
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

## Running Locally

### Requirements

```text
Node.js
npm
Python 3
PostgreSQL
Redis
```

### Clone

```bash
git clone https://github.com/agcodes0315/cybershield-project.git
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

Start FastAPI:

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

---

## Environment Configuration

Example API gateway configuration:

```env
NODE_ENV=development
PORT=5000
DATABASE_URL=postgresql://postgres:password@localhost:5432/cybershield
JWT_SECRET=replace_with_a_secure_secret
DETECTION_ENGINE_URL=http://127.0.0.1:8000
CORS_ORIGINS=http://localhost:5173
REDIS_URL=
```

Frontend:

```env
VITE_API_BASE_URL=http://127.0.0.1:5000/api
VITE_WS_URL=ws://127.0.0.1:5000/ws
```

Production credentials and provider API keys should never be committed to the repository.

---

## Testing

CyberShield includes automated tests across graph analysis, security workflows, incident response and audit integrity.

Latest verified run:

```text
140 passed
```

Coverage includes:

* BFS minimum-hop paths
* Dijkstra weighted paths
* DFS blast-radius analysis
* graph indexing
* critical-asset discovery
* remediation ranking
* MITRE ATT&CK mapping
* event correlation
* UEBA workflows
* prediction workflows
* response approval
* response execution
* audit-chain integrity
* API integration workflows

---

## Reproducibility

The graph-performance measurements referenced in this README are backed by committed benchmark artifacts.

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

This makes the reported optimization inspectable rather than presenting performance claims without supporting artifacts.

---

## Current Limitations

CyberShield is a defensive-security engineering project and not a production replacement for Microsoft Sentinel, Splunk, CrowdStrike or a commercial SOAR platform.

Current limitations include:

* MITRE mapping is currently keyword-oriented
* external intelligence depends on configured provider APIs
* providers may impose rate limits
* cloud environments may restrict network scanning
* WebSocket behavior depends on proxy and container configuration
* Redis is used for low-latency state and caching where configured
* distributed queue behavior has not been independently benchmarked at production scale

These limitations are documented intentionally because understanding where a system stops is part of designing it responsibly.

---

## Future Work

| Area                     | Direction                              |
| ------------------------ | -------------------------------------- |
| ATT&CK Visualization     | Interactive coverage matrix            |
| Behaviour Analytics      | Rolling baselines and anomaly scoring  |
| SIEM Integration         | Sentinel and Splunk event export       |
| Historical Attack Graphs | Path evolution over time               |
| Threat Correlation       | Confidence-scored IOC relationships    |
| Analyst Assistant        | Read-only, RBAC-constrained assistance |
| Kubernetes               | AKS-based orchestration                |
| Streaming Analytics      | Event Hubs or Kafka                    |

---

## Documentation

| Resource                    | Location                                                                                             |
| --------------------------- | ---------------------------------------------------------------------------------------------------- |
| System Design               | [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md)                                                   |
| High-Level Architecture     | [`docs/images/hld.drawio.png`](./docs/images/hld.drawio.png)                                         |
| API Flow                    | [`docs/images/api-flow.drawio.png`](./docs/images/api-flow.drawio.png)                               |
| Authentication Flow         | [`docs/images/auth-flow.drawio.png`](./docs/images/auth-flow.drawio.png)                             |
| Threat Pipeline             | [`docs/images/threat-pipeline.drawio.png`](./docs/images/threat-pipeline.drawio.png)                 |
| Response Flow               | [`docs/images/response-flow.drawio.png`](./docs/images/response-flow.drawio.png)                     |
| Feature Workflow            | [`docs/images/feature-workflow.drawio.png`](./docs/images/feature-workflow.drawio.png)               |
| Entity Relationship Diagram | [`docs/images/ER_Diagram_Clean.drawio.png`](./docs/images/ER_Diagram_Clean.drawio.png)               |
| Deployment Architecture     | [`docs/images/deployment_architecture.drawio.png`](./docs/images/deployment_architecture.drawio.png) |
| Benchmark Artifacts         | [`evaluation/`](./evaluation/)                                                                       |

---

## Responsible Use

CyberShield is intended for:

* defensive security
* authorized security testing
* security engineering education
* research
* portfolio demonstration

Reconnaissance, scanning or security-testing functionality should only be used against systems you own or have explicit permission to assess.

---

## Author

### Agrima Saxena

**Software Engineering · Applied AI · Cybersecurity**

[GitHub](https://github.com/agcodes0315) · [LinkedIn](https://www.linkedin.com/in/agrima-saxena-142960426/) · [Live Demo](https://mango-pebble-099d8de00.7.azurestaticapps.net/)

**Repository:** [github.com/agcodes0315/cybershield-project](https://github.com/agcodes0315/cybershield-project)

---

**CyberShield explores what happens after detection: how evidence becomes context, context becomes a response recommendation, and high-impact actions remain accountable to a human analyst.**
