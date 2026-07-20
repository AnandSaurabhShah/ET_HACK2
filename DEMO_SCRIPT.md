# Demo Script

1. Start backend with `cd backend`, `python seed.py`, then `uvicorn app.main:app --reload`.
2. Start frontend with `cd frontend`, `npm run dev`.
3. Open `http://localhost:5173` and sign in as `SOC-AEGIS-001 / security`.
4. Call out KPI tiles: detection rate, FP rate, ATT&CK accuracy, MTTD, MTTR, autonomous playbook percent.
5. Point out the background traffic strip. Let it run for a moment so benign counts tick up and alerts arrive unprompted.
6. Use **Pause Traffic** if you want a controlled demo, then use **Resume Traffic** to show autonomy.
7. Select a high-severity alert and show its ATT&CK technique, confidence, retrieved evidence, and mitigations.
8. Click **Simulate T1110** in the SOC dashboard, or run `python tools/attack_simulator.py --technique T1110 --count 8`, and show the SSE alert feed updating live.
9. Click **Run playbook**. Show low-blast-radius steps execute and endpoint isolation queue for approval. If Docker Desktop is running, `block_ip` and approved `isolate_endpoint` execute in the throwaway Docker sandbox and show verified evidence; otherwise they show unverified fallback evidence.
10. Approve the run and show the audit table hash chain updating.
11. Show the CVE queue ranked by asset criticality, exploitability, observed TTP overlap, and source (`nvd_live`, `cached`, or `static_fallback`).
12. Click **Simulate** in the digital twin and explain that it is model-only.
13. Switch briefly to candidate login and make a failed login; return to SOC and show ingestion if a new alert is raised.
