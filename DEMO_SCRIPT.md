# Demo Script

1. Start backend with `cd backend`, `python seed.py`, then `uvicorn app.main:app --reload`.
2. Start frontend with `cd frontend`, `npm run dev`.
3. Open `http://localhost:5173` and sign in as `SOC-AEGIS-001 / security`.
4. Call out KPI tiles: detection rate, FP rate, ATT&CK accuracy, MTTD, MTTR, autonomous playbook percent.
5. Select a high-severity alert and show its ATT&CK technique, confidence, retrieved evidence, and mitigations.
6. Click **Simulate T1110** in the SOC dashboard, or run `python tools/attack_simulator.py --technique T1110 --count 8`, and show the SSE alert feed updating live.
7. Click **Run playbook**. Show low-blast-radius steps execute and endpoint isolation queue for approval. If Docker Desktop is running, `block_ip` and approved `isolate_endpoint` execute in the throwaway Docker sandbox and show verified evidence; otherwise they show unverified fallback evidence.
8. Approve the run and show the audit table hash chain updating.
9. Show the CVE queue ranked by asset criticality, exploitability, observed TTP overlap, and source (`nvd_live`, `cached`, or `static_fallback`).
10. Click **Simulate** in the digital twin and explain that it is model-only.
11. Switch briefly to candidate login and make a failed login; return to SOC and show ingestion if a new alert is raised.
