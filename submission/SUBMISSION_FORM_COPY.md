# Submission Form Copy

## Project Title

Aegis-CNI: AI Cyber Resilience For Critical National Exam Infrastructure

## One-Line Description

Aegis-CNI detects live cyberattacks on a CBSE-style exam portal, predicts attack progression, maps evidence to MITRE ATT&CK with GenAI attribution, blocks malicious sources, simulates impact in a digital twin, and proves every response through hash-chained audit logs.

## Problem Statement Alignment

The ET GenAI Hackathon problem asks for an AI-powered cyber-resilience platform for critical national infrastructure that can autonomously detect abnormal behaviour, map attack progression, simulate impact, and orchestrate mitigation. Aegis-CNI implements this for digital examination infrastructure, where downtime or data leakage can directly affect public trust, examination integrity, and student records.

## What We Built

We built a protected CBSE-style examination portal and a live SOC backend. The backend monitors HTTP requests and portal telemetry, detects attacks using anomaly detection and predictive ML, attributes them to MITRE ATT&CK, generates defensive GenAI explanations, blocks malicious source IPs, runs SOAR playbooks, prioritises CVEs, and updates a cyber-resilience digital twin.

## GenAI Usage

GenAI is used for defensive SOC attribution and operator assistance. The system uses online Ollama when available, local Ollama when offline, and deterministic fallback when neither is reachable. SOC Copilot is scope-limited to portal-security and incoming-attack questions. AI prompt-injection and model-secret exfiltration attempts are blocked before GenAI execution.

## AI/ML Usage

The system uses IsolationForest anomaly detection, z-score behavioural baselines, predictive-risk scoring, rare sequence modelling, short-window entity pressure, MITRE ATT&CK retrieval, and graph-based attack-path analysis. Alerting is based on behaviour patterns, not only database lookup.

## Key Features

- Live terminal/API attack detection.
- AI-based malicious source IP blocking.
- MITRE ATT&CK mapping.
- GenAI SOC Copilot.
- AI prompt-injection and jailbreak protection.
- Open redirect prevention.
- IP spoofing prevention through trusted-proxy handling.
- Password policy blocking sensitive-info reuse.
- Two-factor authentication challenge flow.
- Cyber-resilience digital twin.
- CVE prioritisation.
- SOAR playbooks with approval gates.
- Hash-chained audit log.

## Impact

The generated evaluation reports:

- 80.56% detection rate.
- 100.00% ATT&CK attribution accuracy.
- 10080.0x MTTD improvement over a simulated manual SOC baseline.
- 68.6x MTTR improvement over a simulated manual response baseline.
- 697 local ATT&CK techniques loaded for attribution and simulation.

## Differentiator

Most hackathon cyber dashboards show seeded incidents. Aegis-CNI reacts to live terminal attacks, blocks the source, updates the SOC dashboard, explains the evidence, simulates the impact, and verifies the response through audit. It also protects the GenAI layer itself from prompt injection and secret-exfiltration attempts.

## Honest Production Readiness

This is a production-shaped prototype. It already demonstrates the full cyber-resilience loop end to end, but real deployment would require connecting live SIEM, EDR, IAM, WAF/firewall, cloud audit, CMDB, and notification systems. The repository documents those integration points.

## Demo Links

```text
GitHub: https://github.com/AnandSaurabhShah/ET_HACK2
Frontend: <add deployed frontend URL>
Backend health: <add backend /health URL>
Backend readiness: <add backend /ready URL>
Demo video: <add uploaded video URL>
```

## Demo Credentials

```text
SOC: SOC-AEGIS-001 / security
Candidate: CAND-2026-004821 / candidate
Invigilator: INV-DEL-0097 / invigilator
Examiner: OSM-7731 / examiner
```

