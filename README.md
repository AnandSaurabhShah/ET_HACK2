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
- Local ATT&CK corpus built from MITRE Enterprise ATT&CK STIX JSON, distilled to non-deprecated attack techniques and mitigation relationships.
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

## MITRE Coverage

`python seed.py` builds a local corpus from the official MITRE Enterprise ATT&CK STIX JSON and stores the distilled result in `backend/app/rag/fixtures/mitre_enterprise_techniques.json`. The current seeded corpus contains all non-deprecated Enterprise ATT&CK attack-pattern entries found in that source at seed time, including mitigation relationships where MITRE publishes them. Runtime does not depend on live MITRE or CVE internet calls.

Zip archives in the workspace were not used.

## Safe ATT&CK Live Testing

I cannot provide real exploit or malware code for ATT&CK techniques. For live validation, use the safe telemetry simulator:

```bash
cd backend
python tools/attack_simulator.py --list --limit 30
python tools/attack_simulator.py --list --tactic credential-access
python tools/attack_simulator.py --technique T1110 --count 8
```

This sends benign labelled events to `/ingest/events`, so the SOC can detect and audit the selected technique without attacking the machine.

The SOC dashboard also includes a **Simulate T1110** button that triggers the same safe live flow through the backend.

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
