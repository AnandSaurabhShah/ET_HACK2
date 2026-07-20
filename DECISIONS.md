# Decisions

1. The existing `frontend/` app is the protected exam infrastructure, so the candidate, invigilator, examiner, and certificate flows were preserved.
2. A fourth role, `security`, was added through the same auth and role-home pattern as the original roles.
3. The backend is deterministic by default. `python seed.py` prepares local telemetry, ATT&CK, CVE, alert, audit, and eval artifacts before demos.
4. MITRE coverage is sourced from Enterprise ATT&CK STIX and distilled locally instead of hardcoding a small static list. A small fallback exists only for offline first-run failure.
5. The anomaly score combines IsolationForest with z-score deviation because the prompt explicitly asks for both behavioural anomaly detection and baseline deviation scoring.
6. Playbook actions are executable against the mock environment. Endpoint isolation and session revocation are represented as auditable control actions; high-blast-radius actions are queued for human approval.
7. The digital twin is explicitly labelled model-only and never mutates live frontend state.
8. ChromaDB corpus persistence is implemented, while deterministic TF-IDF retrieval remains the fallback path to avoid demo failure on local Chroma issues.
9. The existing zip files in the workspace were not opened, extracted, or used.

