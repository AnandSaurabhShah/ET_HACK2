# ET GenAI Hackathon 2.0 Pitch Pack

## One-Line Claim

Aegis-CNI is an AI cyber-resilience layer for critical exam infrastructure that detects abnormal behaviour, predicts attack progression, maps evidence to MITRE ATT&CK with GenAI attribution, and executes auditable containment within seconds.

## Why It Fits The Problem

- Behavioural anomaly detection: IsolationForest and z-score baselines over users, devices, segments, latency, bytes, and event patterns.
- Predictive risk: gradient-boosted attack probability, rare transition modelling, and entity pressure scoring.
- GenAI attribution: defensive-only attribution synthesis with ATT&CK evidence, likely next stage, and response recommendation.
- SOAR containment: block IP, snapshot state, revoke session, and queue high-blast-radius isolation for approval.
- Vulnerability prioritisation: asset inventory plus NVD CVE cache ranked by CVSS, exploitability, criticality, and observed TTP overlap.
- Digital twin: graph-based attack-path modelling without touching production.
- Auditability: every automated action is written to a hash-chained audit log.

## Winning Demo Flow

1. Open the SOC dashboard; live alert feed is empty.
2. Show ATT&CK coverage heatmap: green live controls, blue attribution/simulation, yellow external connector requirements.
3. Run a CMD/PowerShell attack request.
4. Watch a live alert appear with changing score, latency, and request bytes.
5. Open attribution: MITRE technique, GenAI explanation, model evidence, and likely next stage.
6. Open timeline: observed -> scored -> attributed -> blocked -> playbook queued/executed -> audit hash.
7. Show follow-up request returns real HTTP 403.
8. Ask SOC Copilot: "Why was this blocked?" or "What should I do next?"
9. Show CVE queue updates when live TTPs overlap relevant assets.
10. Verify `/audit/verify` returns `ok: true`.

## Architecture

```text
Exam Portal / CMD / API Client
        |
        v
FastAPI Request Middleware
        |
        +--> Signature + Rate Signals
        +--> Unsupervised Anomaly Agent
        +--> Predictive Risk Agent
        |
        v
Alert Decision Engine
        |
        +--> MITRE RAG Retriever
        +--> GenAI Attribution Provider
        +--> CVE Prioritisation Agent
        +--> Digital Twin Graph
        |
        v
SOAR Orchestrator
        |
        +--> Middleware IP Blocklist
        +--> Sandbox Executor
        +--> Approval Gate
        |
        v
Hash-Chained Audit Log + SOC Dashboard
```

## Production Expansion Path

The code includes production connector interfaces for:

- SIEM telemetry
- EDR containment
- IAM/session control
- Firewall/WAF enforcement
- Cloud audit logs
- OT/industrial sensor telemetry

These are shown in the dashboard so judges can see the path from hackathon prototype to real national-infrastructure deployment.

## Honest Coverage Statement

Aegis-CNI loads the MITRE Enterprise ATT&CK corpus for attribution and simulation. It actively detects and mitigates selected live web/API and identity attack patterns today. Full active coverage across the entire Enterprise matrix requires real SIEM, EDR, IAM, firewall, cloud, and OT integrations.
