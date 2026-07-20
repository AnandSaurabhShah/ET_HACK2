# Aegis-CNI

AI-driven cyber resilience layer for the Pariksha Kendra national exam portal. The existing Vite/React exam app is treated as the protected critical infrastructure; Aegis-CNI adds a fourth `security` role with a SOC Command Center plus a FastAPI applied-ML backend.

## Run

Backend:

```bash
cd backend
pip install -r requirements.txt
python seed.py
uvicorn app.main:app --reload
```

Production-shaped local stack:

```bash
docker compose up --build
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`, choose **Security (SOC Command Center)**, and sign in with:

```text
SOC-AEGIS-001 / security
```

Other demo accounts remain unchanged:

```text
CAND-2026-004821 / candidate
INV-DEL-0097 / invigilator
OSM-7731 / examiner
```

One-command Windows demo:

```powershell
.\scripts\start_demo.ps1
```

## What Is Built

- Existing exam portal extended with a `security` role.
- Frontend auth and public certificate verification events post to `/ingest/events`.
- FastAPI backend with stable endpoints for alerts, SSE, attribution, playbooks, CVE queue, digital twin, audit, and eval report.
- Behavioural anomaly engine using IsolationForest plus z-score deviation against normal baselines.
- Predictive risk engine using gradient-boosted attack probability, rare transition modelling, and entity pressure features.
- Local ATT&CK corpus built from MITRE Enterprise ATT&CK STIX JSON, distilled to non-deprecated attack techniques and mitigation relationships.
- GenAI attribution boundary for defensive evidence synthesis, likely next-stage prediction, and recommendations, with deterministic offline fallback.
- ChromaDB persistence path for the ATT&CK corpus, with deterministic TF-IDF retrieval fallback for offline demos.
- Hash-chained append-only audit log for every automated action.
- `RESULTS.md` generated from the eval harness, not hand-entered metrics.

## What's Real vs. Simulated

Real:

- The frontend role flow and SOC UI are runnable React screens.
- Frontend login, failed login, logout, registration, and certificate lookup events are ingested by the backend.
- IsolationForest and z-score anomaly scoring run against the seeded labelled dataset.
- ATT&CK technique records and mitigations are distilled from MITRE Enterprise ATT&CK STIX data.
- Playbook execution writes hash-chained audit entries and high-blast-radius steps require approval.
- `/eval/report` and `RESULTS.md` are generated from `app/eval/harness.py`.
- Predictive scoring uses learned behavioural patterns and sequence rarity; it does not merely search for a known attack name in a database.

SIMULATED/MOCKED:

- Synthetic telemetry in `app/ingest/synth_generator.py` models exam infrastructure activity and injected campaigns.
- Synthetic CVE feed in `seed.py` models government infrastructure remediation prioritisation.
- Digital twin attack simulation is model-only and never touches a live frontend session.
- LLM reasoning defaults to deterministic offline text; no paid API is required.
- Manual SOC MTTD/MTTR baselines are labelled simulated baselines for comparison.

## API

- `POST /ingest/events`
- `GET /alerts/stream`
- `GET /alerts`
- `GET /attribution/{alert_id}`
- `POST /playbooks/{alert_id}/run`
- `POST /playbooks/{run_id}/approve`
- `GET /cve-queue`
- `GET /twin/graph`
- `POST /twin/simulate`
- `GET /audit`
- `GET /audit/verify`
- `GET /eval/report`
- `GET /ready`
- `GET /demo/status`
- `POST /demo/pause`
- `POST /demo/resume`

Live request-layer detection is documented in [TESTING.md](./TESTING.md). It includes curl/PowerShell checks for SQL injection-shaped payloads, command injection-shaped payloads, path traversal, XSS, scanner User-Agents as supporting signals, endpoint enumeration, brute force, HTTP 403 block enforcement, and audit verification.

Production deployment boundaries and required enterprise integrations are documented in [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md).

## MITRE Coverage

`python seed.py` builds a local corpus from the official MITRE Enterprise ATT&CK STIX JSON and stores the distilled result in `backend/app/rag/fixtures/mitre_enterprise_techniques.json`. The current seeded corpus contains all non-deprecated Enterprise ATT&CK attack-pattern entries found in that source at seed time, including mitigation relationships where MITRE publishes them. Runtime does not depend on live MITRE or CVE internet calls.

Zip archives in the workspace were not used.

## Live CMD/PowerShell Attack Testing

The SOC dashboard feed is live-only by default. Seeded/evaluation alerts train and validate the model, but they are not shown in the dashboard's live alert feed. To make an alert appear, send a request-layer attack shape from CMD, PowerShell, curl, or another HTTP client as documented in [TESTING.md](./TESTING.md).

The safe telemetry simulator is still available for development, but it is no longer exposed as a dashboard button:

```bash
cd backend
python tools/attack_simulator.py --list --limit 30
python tools/attack_simulator.py --list --tactic credential-access
python tools/attack_simulator.py --technique T1110 --count 8
```

This sends benign labelled events to `/ingest/events`; use it only when you explicitly want simulator data.

## Background Demo Traffic

Background demo traffic is disabled by default (`AEGIS_DEMO_BACKGROUND_ENABLED=false`) so the dashboard does not continuously display sample requests.

If you deliberately enable it, the backend can still run the old sample traffic task:

- Every 3-8 seconds it sends one benign synthetic exam-portal telemetry event through the same scoring/attribution/persistence/audit pipeline as `/ingest/events`.
- Roughly every 45-90 seconds it injects one safe ATT&CK simulation event.

Terminal controls:

```bash
curl http://127.0.0.1:8000/demo/status
curl -X POST http://127.0.0.1:8000/demo/pause
curl -X POST http://127.0.0.1:8000/demo/resume
```

## Sandboxed Playbook Execution

`orchestrator_agent.py` now executes playbook steps through `SandboxExecutor`:

- `snapshot_state` writes verifiable local evidence.
- `revoke_session:*` writes verifiable local revocation evidence.
- `block_ip:*` creates/uses a throwaway Docker sandbox and adds a blackhole route when Docker is running.
- `isolate_endpoint:*` disconnects the throwaway Docker endpoint from the sandbox network after human approval.

If Docker is not running, those Docker-backed actions are marked `unverified` and a fallback evidence file is written. Start Docker Desktop before the demo if you want the `block_ip` and `isolate_endpoint` rows to show verified sandbox execution.

## Production Configuration

Copy `backend/.env.example` and `frontend/.env.example` before running a hardened environment. In development, `AEGIS_API_KEY` is optional; when it is set, high-impact routes such as playbook execution and approval require `X-Aegis-Api-Key`.

Production-hardening endpoints:

```bash
curl http://127.0.0.1:8000/ready
curl http://127.0.0.1:8000/audit/verify
```

The backend mirrors telemetry, alerts, and audit entries into SQL through SQLAlchemy. Development defaults to SQLite at `backend/app/data/aegis.db`; production should set `AEGIS_DATABASE_URL` to Postgres.
