# Technical Brief

## System Architecture

```text
CBSE-style Portal / Terminal Attack / API Client
        |
        v
FastAPI Always-On Security Middleware
        |
        +--> Signature signals
        +--> Rate and brute-force signals
        +--> Open redirect guard
        +--> Trusted-proxy/IP spoofing guard
        +--> AI prompt-injection guard
        |
        v
Telemetry Event Pipeline
        |
        +--> IsolationForest anomaly model
        +--> z-score baseline deviation
        +--> predictive risk model
        +--> rare sequence and entity-pressure features
        |
        v
Alert Decision Engine
        |
        +--> MITRE ATT&CK retriever
        +--> GenAI attribution provider
        +--> CVE prioritisation
        +--> Digital twin graph
        |
        v
SOAR + Audit
        |
        +--> source IP block
        +--> session revoke evidence
        +--> snapshot evidence
        +--> approval gate
        +--> hash-chained audit log
```

## Backend

- Framework: FastAPI
- Model stack: scikit-learn, NetworkX, local ATT&CK corpus
- Persistence: JSONL plus SQLAlchemy database mirror
- Streaming: SSE alert feed
- GenAI: online Ollama first, local Ollama second, deterministic offline fallback
- Audit: append-only hash chain

## Frontend

- Framework: Vite React
- Portal style: CBSE-like public services plus role-scoped areas
- SOC dashboard: live alerts, attribution, active blocks, timeline, CVE queue, digital twin, connector readiness, Copilot, and audit table
- Auth hardening: password policy and two-factor authentication demo flow

## Active Live Attack Classes

| Attack Class | Detection Layer | Response |
| --- | --- | --- |
| SQL injection shape | Middleware signature + ML scoring | Alert + IP block |
| Command injection shape | Middleware signature + ML scoring | Alert + IP block |
| Path traversal shape | Middleware signature + ML scoring | Alert + IP block |
| XSS shape | Middleware signature + ML scoring | Alert + IP block |
| Brute-force pressure | Rate and failed-login tracker | Alert + IP block |
| Endpoint enumeration | Sliding-window endpoint diversity | Alert + IP block |
| Open redirect | Redirect allowlist policy | Alert + IP block |
| IP spoofing | Trusted proxy policy | Header ignored or blocked |
| AI prompt injection | AI-attack signature guard | Alert + IP block |
| Copilot jailbreak/API-key exfiltration | Copilot AI guard | Refusal before GenAI call |

## GenAI Safety Boundary

The system prompt forces defensive JSON-only output. A deterministic guard blocks Copilot prompt injection before online Ollama execution. If online GenAI is unavailable or returns invalid JSON, the system falls back to local Ollama or deterministic defensive attribution.

## Digital Twin

The cyber-resilience digital twin models:

- assets and services;
- asset criticality;
- live alert pressure;
- blocked source count;
- controls attached to each asset;
- lateral attack-path edges;
- risk-before and risk-after what-if simulation.

The twin is model-only and does not touch a real user session or production network.

## Production Path

To become a real enterprise deployment, connect:

- SIEM: Splunk, Sentinel, Elastic, Chronicle, or OpenTelemetry/Kafka
- EDR: Microsoft Defender, CrowdStrike, SentinelOne
- IAM: Entra, Okta, Keycloak, LDAP/AD
- Network enforcement: WAF, firewall, gateway, load balancer, cloud security groups
- Asset source: CMDB, cloud inventory, vulnerability scanner
- Ops: Redis blocklist, Postgres/Timescale, object evidence storage, metrics, tracing, alert fatigue monitoring

