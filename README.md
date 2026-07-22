<div align="center">

# 🛡️ CyberShield
### AI-Powered Security Operations Center (SOC) Platform for Critical National Infrastructure

[![React](https://img.shields.io/badge/Frontend-React-61DAFB?logo=react)]()
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)]()
[![Node.js](https://img.shields.io/badge/API-Express.js-339933?logo=node.js)]()
[![Azure](https://img.shields.io/badge/Cloud-Microsoft%20Azure-0078D4?logo=microsoftazure)]()
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791?logo=postgresql)]()
[![Redis](https://img.shields.io/badge/Cache-Redis-DC382D?logo=redis)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

**CyberShield** is a production-inspired **AI-powered Security Operations Center (SOC)** platform designed to improve cyber resilience across Critical National Infrastructure (CNI). The platform combines AI-assisted threat intelligence, phishing detection, cyber resilience analytics, vulnerability prioritization, response orchestration, and cloud deployment into a unified operational dashboard.

Built as a modular, cloud-ready cybersecurity platform, CyberShield demonstrates how modern SOCs leverage Artificial Intelligence, automation, and security analytics to reduce incident response time while improving operational visibility.

</div>

---

# 📌 Table of Contents

- Overview
- Problem Statement
- Key Features
- System Architecture
- Technology Stack
- Implemented Modules
- Screenshots
- AI Capabilities
- Security Features
- Project Structure
- Installation
- Azure Deployment
- API Documentation
- Testing
- Future Enhancements
- Resume Highlights
- Author

---

# 🌍 Overview

Modern organizations rely on multiple disconnected security tools for phishing detection, vulnerability assessment, malware analysis, email investigation, and incident response.

This fragmented approach results in:

- Alert fatigue
- Slow investigations
- High Mean Time to Detect (MTTD)
- High Mean Time to Respond (MTTR)
- Manual security operations

CyberShield unifies these capabilities into a centralized Security Operations Center powered by Artificial Intelligence and cloud-native architecture.

---

# 🎯 Problem Statement

Critical National Infrastructure (CNI) sectors including Government, Defence, Healthcare, Finance, Transportation and Energy face increasingly sophisticated cyber attacks.

Traditional cybersecurity systems rely on isolated security products and signature-based detection methods.

CyberShield addresses this challenge through:

- AI-assisted threat intelligence
- Behaviour-driven security analytics
- Automated response orchestration
- Vulnerability prioritization
- Cyber resilience assessment
- Cloud-native SOC architecture

---

# ✨ Key Features

## Security Operations

- SOC Command Center Dashboard
- Real-time Security Monitoring
- Threat Feed Dashboard
- Analyst Workspace

## Threat Intelligence

- AI URL Scanner
- Email Header Analyzer
- SPF/DKIM/DMARC Validation
- Reconnaissance Engine
- IP Reputation Analysis

## Vulnerability Management

- Vulnerability Prioritization
- Context-aware Risk Scoring
- Patch Prioritization
- Asset Criticality Ranking

## Malware Detection

- YARA Rule Engine
- Malware Signature Analysis
- IOC Detection

## Incident Response

- Human Approval Workflow
- Response Orchestrator
- Automated Playbooks
- Audit Trail
- Response Execution History

## Cyber Resilience

- End-to-End Resilience Analysis
- Security Event Correlation
- Organizational Risk Assessment

## Collaboration

- Community Threat Intelligence
- Shared Security Reports
- Analyst Collaboration

---

# 🏗️ System Architecture

```
                     ┌────────────────────────────┐
                     │        React Frontend      │
                     │   Security Dashboard (UI)  │
                     └─────────────┬──────────────┘
                                   │
                                   ▼
                     ┌────────────────────────────┐
                     │      Express API Gateway   │
                     │ Authentication • Routing   │
                     └─────────────┬──────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
         FastAPI Detection Engine         Authentication
                    │
      ┌─────────────┼──────────────────────────────┐
      ▼             ▼              ▼               ▼
 Email Analysis  URL Scanner   Recon Engine   YARA Engine
      ▼             ▼              ▼               ▼
 Vulnerability Prioritization • Response Orchestrator
      ▼
 Cyber Resilience Engine
      ▼
 PostgreSQL • Redis • Azure
```

---

# 🧠 AI Capabilities

CyberShield integrates AI-assisted cybersecurity analytics including:

- Threat Intelligence Correlation
- Context-aware Vulnerability Prioritization
- Behaviour-based Risk Analysis
- Incident Response Recommendation
- Security Event Correlation
- Email Spoofing Detection
- Phishing URL Detection
- Organizational Cyber Resilience Assessment

---

# 🛠 Technology Stack

### Frontend

- React
- Vite
- CSS3
- Axios

### Backend

- FastAPI
- Node.js
- Express.js
- Python

### Database

- PostgreSQL
- Redis

### Security

- JWT Authentication
- Password Hashing
- Rate Limiting
- Input Validation
- Audit Logging

### Cloud

- Microsoft Azure
- Azure Static Web Apps
- Azure Container Apps

---

# 📂 Implemented Modules

| Module | Description |
|----------|------------|
| SOC Dashboard | Centralized Security Operations Dashboard |
| URL Scanner | AI-assisted phishing URL detection |
| Email Analyzer | Email authentication and spoofing analysis |
| Reconnaissance | Domain intelligence and attack surface discovery |
| Breach Checker | Credential exposure verification |
| Pen Testing | Controlled vulnerability assessment |
| YARA Scanner | Malware detection using YARA rules |
| GoPhish Simulator | Security awareness campaigns |
| Cyber Resilience | Organizational resilience analytics |
| Response Orchestrator | Automated response workflows |
| SOC Community | Threat intelligence collaboration |
| Settings | Workspace management |

---

# 📷 Screenshots

> Add screenshots here

## Dashboard

<img src="screenshots/dashboard.png"/>

---

## Email Analyzer

<img src="screenshots/email-analyzer.png"/>

---

## Cyber Resilience

<img src="screenshots/resilience.png"/>

---

## Response Orchestrator

<img src="screenshots/orchestrator.png"/>

---

## Pen Testing

<img src="screenshots/pentest.png"/>

---

# 🔐 Security Features

- JWT Authentication
- Password Hashing
- Input Sanitization
- Role-based Access
- Audit Logging
- Human Approval Workflows
- API Validation
- Secure Azure Deployment

---

# 🚀 Local Installation

## Clone

```bash
git clone https://github.com/agrima150103/cybershield-project.git

cd cybershield-project
```

---

## Frontend

```bash
cd client

npm install

npm run dev
```

---

## API Gateway

```bash
cd api-gateway

npm install

npm run dev
```

---

## Detection Engine

```bash
cd detection-engine

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

uvicorn app.main:app --reload
```

---

# ☁ Azure Deployment

Frontend deployed using:

- Azure Static Web Apps

Backend deployed using:

- Azure Container Apps

Deployment includes:

- HTTPS
- Environment Variables
- Production API Routing
- Cloud-native Architecture

---

# 📡 API Documentation

FastAPI automatically generates interactive API documentation.

```
/docs
```

Modules include:

- URL Analysis
- Email Analysis
- Reconnaissance
- Vulnerability Prioritization
- Response Orchestration
- Audit
- Cyber Resilience

---

# 🧪 Testing

The platform has been tested using:

- Functional Testing
- Integration Testing
- API Testing
- Authentication Testing
- UI Validation
- Azure Deployment Verification

---

# 📈 Future Enhancements

- MITRE ATT&CK Visualization
- Behavioural Analytics Dashboard
- SIEM Integration
- Threat Actor Attribution
- Kubernetes Deployment
- Graph-based Attack Path Analysis
- AI Security Copilot
- Real-time Streaming Analytics

---

# 📌 Resume Highlights

- Developed a cloud-native AI-powered Security Operations Center using React, FastAPI, Express.js, PostgreSQL, Redis and Microsoft Azure.

- Built modular cybersecurity engines including phishing detection, email intelligence, cyber resilience assessment, vulnerability prioritization, YARA malware analysis and automated response orchestration.

- Implemented secure authentication, audit logging, cloud deployment, REST APIs and production-inspired architecture following modern software engineering practices.

---

# 👩‍💻 Author

**Agrima Saxena**

LinkedIn: https://linkedin.com/in/agrimasaxena

GitHub: https://github.com/agrima150103

---

# ⭐ If you found this project interesting, consider giving it a star!
