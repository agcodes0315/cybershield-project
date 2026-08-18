# 🛡️ CyberShield

### AI-Assisted Security Operations Center for Threat Intelligence, Detection, Response and Cyber Resilience

**A full-stack SOC platform that connects threat intelligence, phishing analysis, reconnaissance, MITRE ATT&CK mapping, attack-path analysis, incident response and analyst-governed remediation in one workflow.**

[![Live Demo](https://img.shields.io/badge/Live_Demo-Open_CyberShield-2563EB?style=for-the-badge\&logo=microsoftazure\&logoColor=white)](https://mango-pebble-099d8de00.7.azurestaticapps.net/)
[![GitHub](https://img.shields.io/badge/GitHub-CyberShield-181717?style=for-the-badge\&logo=github\&logoColor=white)](https://github.com/agcodes0315/cybershield-project)
[![Tests](https://img.shields.io/badge/Tests-140_Passing-22C55E?style=for-the-badge\&logo=pytest\&logoColor=white)](#-testing)

<br/>

<img src="./docs/images/1.jpeg"
  alt="CyberShield SOC Command Center"
  width="100%"/>

<br/>

**Designed and built by [Agrima Saxena](https://github.com/agcodes0315) as a security engineering project focused on detection pipelines, graph algorithms, explainable risk analysis, response orchestration and cloud-ready system design.**

---

## 🚀 What CyberShield Does

Modern security teams rarely work with one source of truth.

Threat intelligence may exist in one tool, phishing analysis in another, attack-path context somewhere else, while incident response decisions are handled manually.

CyberShield brings those workflows together.

An analyst can:

* investigate suspicious URLs, domains, IP addresses and email headers
* collect threat intelligence from external providers
* inspect phishing and spoofing signals
* perform authorized infrastructure reconnaissance
* map findings to MITRE ATT&CK
* analyze attack paths and critical assets
* prioritize remediation using contextual risk
* review automated response recommendations
* approve higher-risk actions manually
* receive real-time WebSocket updates
* verify incident history through a hash-chained audit trail

The objective is not to copy a commercial SIEM or SOAR product feature for feature.

CyberShield explores how the core engineering pieces of a modern security operations platform can be designed, connected, tested and reasoned about as one system.

---

## 🖥️ SOC Command Center

<img src="./docs/images/1.jpeg"
  alt="CyberShield SOC Command Center"
  width="100%"/>

The SOC Command Center provides an operational view of the platform.

It surfaces:

* threat records
* critical threats
* MITRE coverage
* active incidents
* response actions
* detection health
* platform status
* recent threat activity

The dashboard is designed to give an analyst one place to understand current security posture before moving into deeper investigation.

---

## 📊 Engineering Highlights

| Engineering Area                   |                      Result |
| ---------------------------------- | --------------------------: |
| Benchmark graph                    |             **2,500 nodes** |
| Benchmark edges                    |                  **10,000** |
| Critical assets                    |                     **125** |
| Median latency before optimization |              **2461.10 ms** |
| Median latency after optimization  |                 **0.83 ms** |
| Median latency reduction           |                 **~99.97%** |
| Automated tests                    |             **140 passing** |
| Real-time updates                  |              **WebSockets** |
| Cloud deployment                   |         **Microsoft Azure** |
| High-risk response                 | **Human approval required** |

> Performance values come from committed deterministic benchmark artifacts rather than estimated measurements.

---

# 🧭 Security Operations Workflow

CyberShield connects detection, analysis, prioritization and response instead of treating them as independent features.

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
      +------> Threat Intelligence
      |
      +------> Email Analysis
      |
      +------> Reconnaissance
      |
      +------> MITRE ATT&CK
      |
      +------> Attack Graph Context
      |
      v
Unified Risk Evaluation
      |
      v
Response Recommendation
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

---

# 🛡️ Cyber Resilience

<img src="./docs/images/2.jpeg"
  alt="CyberShield Cyber Resilience Dashboard"
  width="100%"/>

The Cyber Resilience workspace turns individual findings into a broader view of organizational risk.

It combines:

* overall risk
* open incidents
* containment progress
* audit integrity
* remediation priorities
* critical asset exposure
* response readiness

This makes it possible to move from "what threat did we detect?" to "what does this mean for the environment?"

---

# ⚡ Response Orchestrator

<img src="./docs/images/3.jpeg"
  alt="CyberShield Response Orchestrator"
  width="100%"/>

CyberShield separates recommendation from authorization.

The Response Orchestrator can:

* prioritize response cases
* identify low-risk actions
* queue higher-risk actions for approval
* execute approved playbooks
* record response history
* maintain incident-state transitions
* verify decisions through the audit layer

High-impact remediation is not silently executed by the system.

### Response Model

```text
Threat Detected
      |
      v
Triaged
      |
      v
Response Recommendation
      |
      v
Risk Threshold
   /        \
  /          \
Low Risk    Medium / High Risk
  |               |
  v               v
Automated      Human Approval
Playbook          Gate
   \              /
    \            /
      v        v
     Execute Response
           |
           v
      Audit Commit
           |
           v
        Closed
```

---

# 📧 Email Threat Analysis

<img src="./docs/images/4.1.jpeg"
  alt="CyberShield Email Threat Analyzer"
  width="100%"/>

The Email Analyzer inspects suspicious headers and authentication evidence.

Analysis includes:

* sender identity
* routing information
* SPF
* DKIM
* DMARC
* Return-Path mismatch
* Reply-To mismatch
* suspicious URLs
* attachment indicators
* impersonation signals
* delivery anomalies

### Example Threat Verdict

<img src="./docs/images/4.jpeg"
  alt="CyberShield Email Spoofing Detection Result"
  width="100%"/>

The analysis workflow explains why an email is suspicious instead of returning only a label.

A verdict can include:

* displayed sender
* actual return path
* authentication failures
* parsed routing hops
* content indicators
* threat score
* final risk classification

---

# 🔍 Reconnaissance

<img src="./docs/images/5.jpeg"
  alt="CyberShield Reconnaissance Module"
  width="100%"/>

The reconnaissance workflow gathers authorized infrastructure intelligence.

Supported analysis includes:

* DNS resolution
* domain information
* IP analysis
* open-port inspection
* abuse reputation
* network context
* external exposure signals

Reconnaissance results are combined with other security context before contributing to risk evaluation.

---

# 🌐 Threat Intelligence Center

<img src="./docs/images/6.jpeg"
  alt="CyberShield Threat Intelligence Center"
  width="100%"/>

CyberShield can aggregate intelligence from external security providers.

Supported integrations include:

* PhishTank
* VirusTotal
* AbuseIPDB
* Shodan
* Have I Been Pwned

The platform treats external intelligence as evidence, not absolute truth.

Provider failures, rate limits or conflicting information should not silently override application logic.

---

# 🧭 MITRE ATT&CK Mapping

<img src="./docs/images/7.jpeg"
  alt="CyberShield MITRE ATT&CK Mapping"
  width="100%"/>

Security findings can be mapped to MITRE ATT&CK tactics and techniques.

The interface allows analysts to:

* inspect mapped techniques
* search ATT&CK IDs
* filter by tactic
* filter by severity
* connect intelligence records to attacker behavior
* review high-priority mappings

MITRE context provides a common language between raw indicators and adversary behavior.

---

# 🔐 Breach Intelligence

<img src="./docs/images/8.jpeg"
  alt="CyberShield Breach Checker"
  width="100%"/>

CyberShield includes credential exposure analysis using the Have I Been Pwned k-Anonymity model.

For password checks:

* the complete password is not sent to the provider
* the password is hashed locally
* only the required SHA-1 prefix is transmitted
* returned suffixes are compared locally

This reduces unnecessary credential exposure during breach checks.

---

# 🏗️ System Architecture

<img src="./docs/images/9.jpeg"
  alt="CyberShield Service Architecture"
  width="100%"/>

CyberShield is divided into independently deployable services.

| Layer                    | Responsibility                                    |
| ------------------------ | ------------------------------------------------- |
| React Application        | SOC interface and analyst workflows               |
| Express API Gateway      | authentication, RBAC, routing and request control |
| FastAPI Detection Engine | detection, enrichment and security analytics      |
| PostgreSQL               | persistent application state                      |
| Redis                    | low-latency cache and coordination                |
| WebSockets               | real-time analyst updates                         |

The service boundary allows the frontend, gateway and detection engine to evolve independently.

---

## 🧩 High-Level Design

<img src="./docs/images/hld.drawio.png"
  alt="CyberShield High-Level Architecture"
  width="100%"/>

The React frontend communicates with an Express API gateway.

The gateway acts as the primary trust boundary for:

* JWT verification
* role-based access control
* request validation
* rate limiting
* security headers
* routing

Analysis workloads are delegated to the FastAPI detection engine.

PostgreSQL stores durable application data while Redis supports low-latency access and shared operational state where configured.

---

# 🔄 API Request Flow

<img src="./docs/images/api-flow.drawio.png"
  alt="CyberShield API Request Flow"
  width="90%"/>

Requests follow a controlled route through the application.

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
Security Middleware
      |
      +------> PostgreSQL CRUD
      |
      +------> FastAPI Analysis
                  |
                  v
             Persist / Cache
                  |
                  v
           WebSocket Broadcast
                  |
                  v
             HTTP Response
```

This keeps authentication and authorization outside the detection engine.

---

# 🔑 Authentication and RBAC

<img src="./docs/images/auth-flow.drawio.png"
  alt="CyberShield Authentication and RBAC Flow"
  width="75%"/>

CyberShield uses JWT authentication with role-aware authorization.

| Role           | View Incidents | Run Playbook | Approve Higher-Risk Action | Manage Users |
| -------------- | :------------: | :----------: | :------------------------: | :----------: |
| Analyst        |        ✅       |       ❌      |              ❌             |       ❌      |
| Senior Analyst |        ✅       |  ✅ Low Risk  |              ✅             |       ❌      |
| SOC Lead       |        ✅       |       ✅      |              ✅             |       ✅      |

Authentication includes:

* BCrypt password verification
* JWT signature validation
* expiry checks
* RBAC permission checks
* login rate limiting

Protected requests must pass authorization before reaching downstream services.

---

# 🧠 Attack Graph Intelligence

CyberShield represents infrastructure relationships as a directed weighted graph.

The attack-graph subsystem supports:

* BFS minimum-hop paths
* Dijkstra lowest-cost paths
* DFS blast-radius analysis
* critical-asset discovery
* compromise reachability
* containment simulation
* remediation prioritization

This allows risk to be evaluated based on possible attacker movement rather than treating findings as isolated alerts.

---

# ⚙️ Algorithm Engineering

One of the largest performance improvements in CyberShield was made in critical-asset discovery.

## Original Approach

The original implementation ran Dijkstra's algorithm independently for each critical asset.

For `K` critical assets:

```text
O(K × (V + E) log V)
```

This produced correct results but repeated much of the same shortest-path computation.

## Optimized Approach

The workflow was redesigned around a single-source shortest-path traversal with hash-set membership checks while evaluating critical assets.

Approximate complexity:

```text
O((V + E) log V + K)
```

## Benchmark Results

| Metric          |     Before |   After |
| --------------- | ---------: | ------: |
| Nodes           |      2,500 |   2,500 |
| Edges           |     10,000 |  10,000 |
| Critical assets |        125 |     125 |
| Mean latency    | 2434.16 ms | 0.84 ms |
| Median latency  | 2461.10 ms | 0.83 ms |
| P95 latency     | 2582.02 ms | 0.90 ms |

### **~99.97% reduction in recorded median latency**

The optimized implementation was also validated against the full automated test suite.

```text
140 passed
```

Benchmark artifacts are stored in:

```text
evaluation/
├── benchmark_graph_algorithms.py
├── graph_algorithm_benchmark_before.csv
├── graph_algorithm_benchmark_after.csv
└── graph_algorithm_verified_run.txt
```

---

# 🧾 Auditable Incident Lifecycle

<img src="./docs/images/response-flow.drawio.png"
  alt="CyberShield Response Flow"
  width="90%"/>

Important state transitions are written to an append-oriented audit history.

Audit entries can contain:

```text
incident_id
actor
action
payload_hash
prev_hash
timestamp
```

Each record can reference the previous record's hash.

Changing historical data unexpectedly can therefore break the chain and become detectable.

---

# 🗄️ Data Model

<img src="./docs/images/ER_Diagram_Clean.drawio.png"
  alt="CyberShield Entity Relationship Diagram"
  width="100%"/>

The persistent model includes:

* users
* roles
* threat entries
* incidents
* responses
* audit records

Key relationships include:

```text
roles          1 -> N users
users          1 -> N threat_entries
users          1 -> N incidents
users          1 -> N responses
threat_entries 1 -> 0..1 incidents
incidents      1 -> N audit_log
incidents      1 -> N responses
```

---

# 🔬 Threat Detection Pipeline

<img src="./docs/images/threat-pipeline.drawio.png"
  alt="CyberShield Threat Detection Pipeline"
  width="90%"/>

The detection pipeline combines local analysis, caching and external intelligence.

A URL or email can move through:

1. request validation
2. authentication and RBAC
3. Redis lookup
4. feature extraction
5. email or URL analysis
6. external threat enrichment
7. ML risk scoring
8. contextual risk weighting
9. MITRE ATT&CK mapping
10. PostgreSQL persistence
11. Redis cache update
12. WebSocket notification

---

# 🔁 End-to-End Feature Workflow

<img src="./docs/images/feature-workflow.drawio.png"
  alt="CyberShield End-to-End Analyst Workflow"
  width="90%"/>

A typical analyst workflow connects several modules instead of ending after detection.

```text
Login
  |
  v
SOC Command Center
  |
  v
IOC / URL / Email Analysis
  |
  v
Threat Intelligence
  |
  v
Optional Reconnaissance
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
  v
Cyber Resilience Update
  |
  v
Audit / Reporting
```

---

# ☁️ Azure Deployment

<img src="./docs/images/deployment_architecture.drawio.png"
  alt="CyberShield Azure Deployment Architecture"
  width="100%"/>

| Component                   | Deployment            |
| --------------------------- | --------------------- |
| Frontend                    | Azure Static Web Apps |
| API Gateway                 | Azure Container Apps  |
| Detection Engine            | Azure Container Apps  |
| Persistent Data             | PostgreSQL            |
| Cache and Operational State | Redis                 |
| Containers                  | Docker                |

The frontend and backend services can be built and deployed independently.

Production checks include:

```http
GET /health/live
GET /health
GET /api/auth/me
GET /api/threats/recent
GET /api/mitre
```

Deployment validation also covers:

* HTTPS
* WSS
* CORS
* authentication
* PostgreSQL connectivity
* Redis connectivity
* detection-engine connectivity
* environment configuration

---

# 🛠️ Technology Stack

| Layer             | Technology         |
| ----------------- | ------------------ |
| Frontend          | React, Vite        |
| HTTP Client       | Axios              |
| Charts            | Recharts           |
| UI Icons          | Lucide React       |
| API Gateway       | Node.js, Express   |
| Detection Engine  | Python, FastAPI    |
| Machine Learning  | scikit-learn       |
| Graph Analysis    | BFS, DFS, Dijkstra |
| Malware Analysis  | YARA               |
| Reconnaissance    | Nmap, WHOIS        |
| Database          | PostgreSQL         |
| Cache / State     | Redis              |
| Authentication    | JWT, BCrypt        |
| Real-Time Updates | WebSockets         |
| Cloud             | Microsoft Azure    |
| Containers        | Docker             |
| Testing           | pytest             |

---

# 📦 Implemented Modules

| Module                   | Purpose                                       |
| ------------------------ | --------------------------------------------- |
| SOC Command Center       | operational security overview                 |
| Cyber Resilience         | organizational risk and response readiness    |
| Response Orchestrator    | analyst-governed incident response            |
| Email Analyzer           | phishing and spoofing analysis                |
| Reconnaissance           | domain and network intelligence               |
| Threat Intelligence      | IOC and reputation analysis                   |
| MITRE ATT&CK             | tactic and technique mapping                  |
| Breach Checker           | credential exposure verification              |
| Attack Graph             | paths, reachability and blast-radius analysis |
| Vulnerability Management | risk prioritization                           |
| YARA Scanner             | malware signature matching                    |
| GoPhish Simulator        | phishing-awareness workflows                  |
| Audit Engine             | incident and decision history                 |
| Settings                 | workspace configuration                       |

---

# 📡 API Surface

## Authentication

```http
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me
```

## URL Analysis

```http
POST /api/scan/url
GET  /api/scan/history
```

## Email Analysis

```http
POST /api/email/analyze
```

## Threat Intelligence

```http
POST /api/threats/fetch
GET  /api/threats/recent
GET  /api/threats/search
```

## MITRE ATT&CK

```http
GET /api/mitre
```

## Reconnaissance

```http
POST /api/recon/port-scan
POST /api/recon/abuse-check
POST /api/recon/full
```

## Incident Response

```http
GET  /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents
POST /api/resilience/orchestrator/incidents/:id/decide
POST /api/resilience/orchestrator/incidents/:id/auto-execute

GET  /api/resilience/audit/trail
GET  /api/resilience/audit/verify
```

FastAPI also provides interactive OpenAPI documentation at:

```text
/docs
```

---

# 📁 Repository Structure

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
│   │   ├── api-flow.drawio.png
│   │   ├── auth-flow.drawio.png
│   │   ├── deployment_architecture.drawio.png
│   │   ├── ER_Diagram_Clean.drawio.png
│   │   ├── feature-workflow.drawio.png
│   │   ├── hld.drawio.png
│   │   ├── response-flow.drawio.png
│   │   └── threat-pipeline.drawio.png
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

# ⚙️ Running Locally

## 1. Clone CyberShield

```bash
git clone https://github.com/agcodes0315/cybershield-project.git
cd cybershield-project
```

## 2. Start the API Gateway

```bash
cd api-gateway
npm install
npm run dev
```

## 3. Start the Detection Engine

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

## 4. Start the Frontend

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

# 🔑 Environment Configuration

## `api-gateway/.env`

```env
NODE_ENV=development
PORT=5000
DATABASE_URL=postgresql://postgres:password@localhost:5432/cybershield
JWT_SECRET=replace_with_a_secure_secret
DETECTION_ENGINE_URL=http://127.0.0.1:8000
CORS_ORIGINS=http://localhost:5173
REDIS_URL=
```

## `client/.env`

```env
VITE_API_BASE_URL=http://127.0.0.1:5000/api
VITE_WS_URL=ws://127.0.0.1:5000/ws
```

Do not commit production secrets, credentials or provider API keys.

---

# 🧪 Testing

CyberShield includes automated tests across security analysis, graph algorithms, response workflows and audit integrity.

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
* prediction workflows
* response approvals
* response execution
* audit-chain integrity
* API integration workflows

---

# 🔬 Reproducibility

Performance experiments are stored under `evaluation/`.

The repository contains:

* benchmark source code
* deterministic graph generation
* before results
* after results
* raw CSV output
* verified benchmark output

This makes the performance claims inspectable rather than relying on approximate statements.

---

# 🔐 Security Controls

CyberShield includes:

* JWT authentication
* BCrypt password hashing
* role-based access control
* request validation
* rate limiting
* Helmet security headers
* CORS restrictions
* parameterized SQL
* WebSocket-controlled updates
* human approval for higher-risk response actions
* hash-chained audit records

---

# ⚠️ Current Scope

CyberShield is a defensive-security engineering and portfolio project.

It is not intended to replace Microsoft Sentinel, Splunk, CrowdStrike, Palo Alto Cortex or a production commercial SOAR platform.

Current limitations include:

* MITRE mapping currently uses keyword-oriented classification
* threat intelligence depends on configured external providers
* external services may enforce rate limits
* network scanning may be restricted by cloud environments
* WebSocket behavior depends on proxy and container configuration
* Redis is used for caching and operational state where configured
* distributed queue behavior has not been independently benchmarked end to end

These limitations are documented intentionally so the boundary between the current implementation and future production engineering remains clear.

---

# 🌱 Future Work

| Area                     | Direction                                    |
| ------------------------ | -------------------------------------------- |
| ATT&CK Visualization     | interactive ATT&CK coverage views            |
| Behaviour Analytics      | rolling baselines and anomaly scoring        |
| SIEM Integration         | event export for Sentinel and Splunk         |
| Threat Actor Context     | confidence-scored IOC correlation            |
| Historical Attack Graphs | topology snapshots and path evolution        |
| Security Assistant       | read-only RBAC-constrained analyst assistant |
| Kubernetes               | AKS service orchestration                    |
| Streaming Analytics      | Event Hubs or Kafka                          |
| Detection Engineering    | broader rule and model evaluation            |
| SOAR Workflows           | richer approval and execution policies       |

---

# 🎯 What This Project Demonstrates

CyberShield brings together several engineering disciplines inside one system:

* security engineering
* backend architecture
* REST API design
* graph algorithms
* algorithm optimization
* machine learning integration
* threat intelligence
* role-based authorization
* real-time communication
* auditability
* cloud deployment
* testing
* human-in-the-loop decision systems

---

# 📚 Documentation

| Resource                    | Location                                                                                             |
| --------------------------- | ---------------------------------------------------------------------------------------------------- |
| High-Level Architecture     | [`docs/images/hld.drawio.png`](./docs/images/hld.drawio.png)                                         |
| API Flow                    | [`docs/images/api-flow.drawio.png`](./docs/images/api-flow.drawio.png)                               |
| Authentication Flow         | [`docs/images/auth-flow.drawio.png`](./docs/images/auth-flow.drawio.png)                             |
| Deployment Architecture     | [`docs/images/deployment_architecture.drawio.png`](./docs/images/deployment_architecture.drawio.png) |
| Entity Relationship Diagram | [`docs/images/ER_Diagram_Clean.drawio.png`](./docs/images/ER_Diagram_Clean.drawio.png)               |
| Feature Workflow            | [`docs/images/feature-workflow.drawio.png`](./docs/images/feature-workflow.drawio.png)               |
| Response Flow               | [`docs/images/response-flow.drawio.png`](./docs/images/response-flow.drawio.png)                     |
| Threat Pipeline             | [`docs/images/threat-pipeline.drawio.png`](./docs/images/threat-pipeline.drawio.png)                 |
| Editable Draw.io Files      | [`docs/diagrams/`](./docs/diagrams/)                                                                 |
| System Design               | [`docs/SYSTEM_DESIGN.md`](./docs/SYSTEM_DESIGN.md)                                                   |
| Evaluation Artifacts        | [`evaluation/`](./evaluation/)                                                                       |

---

# 📄 Responsible Use

CyberShield is intended for:

* defensive-security learning
* authorized security testing
* research
* security engineering demonstrations
* portfolio use

Only run reconnaissance, scanning or other security-testing functionality against infrastructure you own or have explicit permission to assess.

---

# 👩‍💻 Author

## Agrima Saxena

**Software Engineering · Applied AI · Cybersecurity · Security Systems**

<table>
<tr>

<td width="60">
<a href="https://www.linkedin.com/in/agrima-saxena-142960426/" title="LinkedIn">
<img src="https://img.icons8.com/color/48/linkedin.png"
     width="32"
     height="32"
     alt="LinkedIn"/>
</a>
</td>

<td width="60">
<a href="mailto:agrimalc@gmail.com" title="Email">
<img src="https://img.icons8.com/color/48/gmail-new.png"
     width="32"
     height="32"
     alt="Email"/>
</a>
</td>

<td width="60">
<a href="https://github.com/agcodes0315" title="GitHub">
<img src="https://img.icons8.com/ios-glyphs/48/ffffff/github.png"
     width="32"
     height="32"
     alt="GitHub"/>
</a>
</td>

</tr>
</table>

<a href="https://mango-pebble-099d8de00.7.azurestaticapps.net/">
<img src="https://img.shields.io/badge/Live%20Demo-Open%20CyberShield-2563EB?style=flat-square&logo=microsoftazure&logoColor=white"
     alt="CyberShield Live Demo"/>
</a>

<a href="https://github.com/agcodes0315/cybershield-project">
<img src="https://img.shields.io/badge/GitHub-View%20Repository-181717?style=flat-square&logo=github&logoColor=white"
     alt="CyberShield Repository"/>
</a>

<br/><br/>

**CyberShield explores what happens when detection, intelligence, graph analysis and response are treated as one connected security system rather than isolated tools.**
