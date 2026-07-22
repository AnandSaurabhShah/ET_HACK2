# 90-Second Pitch Video Script

## Title

Aegis-CNI: AI Cyber Resilience For Critical Exam Infrastructure

## Script

**0:00-0:10**

India's digital examination infrastructure is critical national infrastructure. A breach can leak student records, disrupt exams, and force emergency shutdowns. Aegis-CNI is built to detect and contain those attacks live.

**0:10-0:25**

This is a CBSE-style exam portal protected by an AI SOC backend. The portal supports candidate, invigilator, examiner, and security roles. Login includes password policy enforcement and two-factor authentication.

**0:25-0:40**

When an attack arrives from terminal or API, FastAPI middleware captures it as telemetry. The event is scored by anomaly detection, predictive risk, rare sequence modelling, and entity pressure analysis.

**0:40-0:55**

The system maps the behaviour to MITRE ATT&CK, asks GenAI for defensive attribution, predicts the likely next stage, and blocks the malicious source IP. A follow-up request receives HTTP 403.

**0:55-1:10**

The SOC dashboard is live. Alerts, risk score, latency, request bytes, active blocks, CVE queue, digital twin, timeline, and audit trail all update from backend data.

**1:10-1:25**

Aegis-CNI also protects the AI layer. Prompt-injection, jailbreak, system-prompt leakage, tool override, and API-key exfiltration attempts are blocked before online Ollama is called.

**1:25-1:30**

Aegis-CNI demonstrates the full resilience loop: detect, predict, attribute, simulate, mitigate, and prove every action with hash-chained audit evidence.

