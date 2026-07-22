# Production Readiness Notes

This repo now implements a production-shaped SOC pipeline, but a true enterprise deployment still depends on live integrations outside the hackathon workspace.

## Implemented In This Codebase

- Always-on FastAPI request middleware for every inbound HTTP request.
- Real HTTP 403 mitigation through an in-memory perimeter blocklist with expiry.
- AI containment agent blocks live malicious source IPs after anomaly/predictive scoring confirms a high-confidence alert.
- AI prompt-injection guard blocks jailbreak, system-prompt leakage, API-key exfiltration, and tool-call override attempts at the HTTP layer and in SOC Copilot before online GenAI execution.
- Trusted-proxy source attribution prevents direct clients from spoofing `X-Forwarded-For`; production deployments must set `AEGIS_TRUSTED_PROXY_IPS` to the real WAF/load-balancer ranges.
- Open-redirect guard rejects unsafe external, protocol-relative, JavaScript, data, and control-character redirect targets before route handling.
- Candidate password policy rejects passwords that reuse roll number, name, email handle, phone suffix, or common exam-portal terms.
- Demo two-factor authentication challenge endpoints are implemented; replace demo OTP disclosure with SMS, email, authenticator app, or institutional IAM MFA in production.
- Signature detection for SQL injection, command injection, path traversal, XSS, scanner User-Agent support signals, and oversized requests.
- Sliding-window behavioural detection for request bursts, endpoint enumeration, and failed login pressure.
- Unsupervised anomaly detection with IsolationForest and z-score deviation from normal baselines.
- Predictive ML risk scoring with a gradient-boosted classifier, rare sequence modelling, and entity pressure features.
- MITRE ATT&CK attribution through a local ATT&CK corpus and retrieval layer.
- GenAI attribution provider boundary for defensive reasoning, likely next stage, and recommended containment actions.
- Deterministic offline GenAI fallback so demos work without external API keys.
- SOAR playbooks with sandboxed block IP, snapshot, revoke session, and endpoint isolation evidence.
- Human approval gates for high-blast-radius actions.
- Live NVD CVE cache with static fallback.
- Hash-chained audit log with verification endpoint.
- Live-only SOC dashboard feed; seeded/eval data trains and validates the model but does not appear as current incidents.
- Cyber-resilience digital twin with asset criticality, live alert pressure, attack-path what-if simulation, control mapping, and post-containment risk projection.

## Pattern-Based Detection

The predictive risk layer does not look up an attack by name in a database. It scores behaviour using:

- categorical event fingerprints for role, event type, segment, user, device, and source network;
- temporal features from event time;
- latency and byte-volume distributions;
- success/failure behaviour;
- short-window entity pressure across user/device/IP;
- rare event and transition modelling learned from normal telemetry;
- live perimeter confidence when middleware has signal evidence.

The final alert decision uses the higher of:

- unsupervised anomaly score;
- predictive risk score.

The dashboard stores both in `event.metadata.model_scores`.

## GenAI Attribution

Default mode is `auto`, which uses the strongest available GenAI path in order:

1. Configured online API while the operator is online and the provider responds.
2. Local Ollama Aegis model.
3. Deterministic offline defensive fallback.

Online API configuration:

```env
AEGIS_GENAI_PROVIDER=auto
AEGIS_GENAI_ONLINE_PROVIDER=openai-compatible
AEGIS_GENAI_ONLINE_ENDPOINT=https://your-provider.example/v1/chat/completions
AEGIS_GENAI_ONLINE_MODEL=your-online-model
AEGIS_GENAI_ONLINE_API_KEY=your-key
AEGIS_GENAI_ENDPOINT=http://127.0.0.1:11434/api/generate
AEGIS_GENAI_MODEL=aegis-cni:latest
AEGIS_GENAI_TIMEOUT_SECONDS=30
```

Create the model with:

```powershell
.\scripts\create_ollama_model.ps1
```

This is a project-tuned Ollama model built from `ollama/Modelfile` with defensive system instructions and SOC examples. True weight fine-tuning can be added later by training a LoRA/adapter externally and referencing it from the Modelfile.

To use a hosted Ollama-compatible API as the online path:

```env
AEGIS_GENAI_PROVIDER=auto
AEGIS_GENAI_ONLINE_PROVIDER=ollama
AEGIS_GENAI_ONLINE_ENDPOINT=https://your-ollama-host.example/api/generate
AEGIS_GENAI_ONLINE_MODEL=aegis-cni:latest
AEGIS_GENAI_ONLINE_API_KEY=optional-bearer-token
```

The prompt is defensive-only and asks for strict JSON:

- evidence;
- likely next stage;
- defensive recommendation.

If the online provider times out or returns invalid JSON, attribution falls back to local Ollama. If local Ollama is unavailable too, it falls back to deterministic defensive output and records the fallback reason in evidence.

## Required For A Real Enterprise Deployment

These are not things a local hackathon repo can truthfully complete by itself:

- SIEM ingestion: Splunk, Sentinel, Elastic, Chronicle, or Kafka/OpenTelemetry pipelines.
- EDR containment: Microsoft Defender, CrowdStrike, SentinelOne, or equivalent endpoint isolation APIs.
- IAM/session control: Azure AD/Entra, Okta, Keycloak, LDAP/AD, or application session revocation.
- Network enforcement: WAF, API gateway, firewall, load balancer, or cloud security group block rules.
- Asset truth source: CMDB, cloud inventory, vulnerability scanner, and patch-management integration.
- Production storage: Postgres/Timescale or warehouse-backed telemetry, Redis-backed blocklists, object storage for evidence.
- Secrets management: vault-backed API keys, rotation, and per-route RBAC.
- Model operations: drift monitoring, labelled feedback loop, shadow deployments, rollback, and periodic retraining.
- Observability: metrics, traces, logs, SLOs, alert fatigue dashboards, and audit export.
- Governance: approval policy, blast-radius definitions, incident retention, privacy review, and red-team validation.

## Deployment Positioning

Honest positioning for judges:

This is a working production-shaped prototype. It demonstrates the full cyber-resilience loop end to end: detection, prediction, attribution, containment, CVE prioritisation, digital twin simulation, and auditability. To become fully production-grade in a real national infrastructure environment, the integration points above must be connected to the organisation's actual control plane.
