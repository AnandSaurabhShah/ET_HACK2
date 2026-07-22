# Aegis-CNI: AI Cyber Resilience For Critical Exam Infrastructure

## The Problem

Critical national examination systems are high-value targets. A successful attack can leak student records, disrupt board examinations, compromise examiner workflows, and force emergency shutdowns. Traditional security tools often react after a known signature exists; the ET GenAI Hackathon problem asks for AI-driven resilience that detects, predicts, maps, simulates, and mitigates attacks faster.

## The Solution

Aegis-CNI is a working AI cyber-resilience layer wrapped around a CBSE-style exam portal. It monitors live HTTP traffic and portal telemetry, scores abnormal behaviour, maps evidence to MITRE ATT&CK, uses GenAI for defensive attribution, blocks malicious sources, and records every action in a hash-chained audit trail.

## What Judges Can See Live

- Run a terminal attack request against the portal.
- Watch a live SOC alert appear through SSE.
- See risk score, latency, bytes, source IP, ATT&CK technique, and predicted next stage update.
- Confirm the source IP is blocked with real HTTP 403 enforcement.
- Ask SOC Copilot why the attack was blocked.
- Run the digital twin to see attack-path and post-containment risk simulation.
- Verify the audit chain with `/audit/verify`.

## Why It Is GenAI-Relevant

- GenAI SOC Copilot answers only portal-security and incoming-attack questions.
- Online Ollama is used when available; local Ollama or deterministic fallback keeps the system available offline.
- GenAI attribution produces defensive evidence, likely next stage, and mitigation recommendations.
- AI-attack guard blocks prompt injection, jailbreaks, system-prompt leakage, tool override, and API-key exfiltration prompts before model execution.

## AI/ML Core

- IsolationForest anomaly scoring.
- Z-score deviation from behavioural baselines.
- Predictive risk model using sequence rarity and entity pressure.
- MITRE ATT&CK retrieval over a local Enterprise ATT&CK corpus.
- Graph-based cyber-resilience digital twin.

## Implemented Defensive Controls

- Malicious source IP blocking.
- SQL injection, command injection, XSS, path traversal, oversized request, brute-force, endpoint enumeration, open redirect, IP spoofing, and AI prompt-injection detection.
- Password policy blocking sensitive-info reuse.
- Two-factor authentication demo flow.
- Human approval gate for high-blast-radius SOAR actions.
- Hash-chained audit log.

## Measured Results

From the generated evaluation report:

- Detection rate: 80.56%
- ATT&CK attribution accuracy: 100.00%
- MTTD improvement over simulated manual baseline: 10080.0x
- MTTR improvement over simulated manual baseline: 68.6x
- Local ATT&CK techniques loaded: 697

## Honest Boundary

This is a production-shaped working prototype. Full enterprise deployment requires connecting real SIEM, EDR, IAM, WAF/firewall, cloud audit, CMDB, and notification systems. The repository includes connector readiness and deployment documentation for that path.

