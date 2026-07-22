# CyberShield — PS7 Add-ons Integration Guide

## What's in this folder
```
detection-engine/app/api/vulnerability_priority.py   # Vulnerability Prioritisation
detection-engine/app/api/audit_log.py                # Hash-chained Audit Integrity
detection-engine/app/api/response_orchestrator.py    # Simulated SOAR + human approval
detection-engine/scripts/evaluation_metrics.py       # Real detection metrics for your PPT
client/src/pages/ResponseOrchestrator.jsx            # UI for the orchestrator
```

## Wiring it in (detection-engine, ~15 min)
In `detection-engine/app/main.py`, add:
```python
from app.api import vulnerability_priority, audit_log, response_orchestrator

app.include_router(vulnerability_priority.router, prefix="/api/vuln-priority")
app.include_router(audit_log.router, prefix="/api/audit")
app.include_router(response_orchestrator.router, prefix="/api/orchestrator")
```
Test locally:
```
curl http://localhost:8000/api/vuln-priority/demo
curl -X POST http://localhost:8000/api/orchestrator/incidents \
  -H "Content-Type: application/json" \
  -d '{"source":"url_scanner","target":"http://paypal-secure-login.xyz","confidence":0.94,"reason":"ML ensemble flagged phishing + YARA credential-harvest match"}'
curl http://localhost:8000/api/audit/trail
curl http://localhost:8000/api/audit/verify
```

## Running the metrics script (5 min)
```
cd detection-engine
python scripts/evaluation_metrics.py
```
Open `detection-engine/evaluation_output/metrics_table.md` and paste it straight into your deck.
**Before you quote the numbers to judges:** swap the stub predictor in
`load_model_and_features()` for your real `predict_url` import, and swap the
sample URLs for your real held-out test split. Ten minutes of work for numbers
you can actually defend under questioning.

## Wiring the React page (~10 min)
1. Copy `ResponseOrchestrator.jsx` into `client/src/pages/`.
2. Fix the `import api from "../services/api"` path to match your actual axios client.
3. Add a route, e.g. in your router file:
   ```jsx
   <Route path="/orchestrator" element={<ResponseOrchestrator />} />
   ```
4. Add a nav link next to your existing Dashboard/Recon/YARA links.

## Proxy it through your Express API gateway (~5 min)
You already proxy other detection-engine routes through Express — add these
three the same way you did for `/api/scan`, `/api/recon`, etc.

## Honesty checklist for your PPT / README (do this, it matters)
| Feature | Status to write | Why |
|---|---|---|
| Phishing/URL ML detection, YARA, recon, breach check | **LIVE** | Already deployed |
| Vulnerability Prioritisation | **LIVE (demo data + your scanner)** | Code above |
| Audit Integrity (hash chain) | **LIVE** | Code above |
| Response Orchestrator | **SIMULATED** | Say this explicitly — no live infra touched |
| Evaluation metrics | **LIVE (once you swap in real model/data)** | Code above |
| MITRE ATT&CK mapping | **PLANNED** | Not implemented — don't claim it |
| Behavioural anomaly / UEBA | **PLANNED** | Not implemented — don't claim it |
| IT/OT telemetry | **PLANNED** | Not implemented — don't claim it |
| Threat-intel RAG | **PLANNED** | Not implemented — don't claim it |
| Digital Twin | **PLANNED** | Not implemented — don't claim it |

Judges consistently score "clear roadmap, honest about scope" higher than
vague claims that don't survive a follow-up question. Given your timeline,
this table is your strongest asset for Innovation + Business Impact without
risking Technical Excellence credibility.