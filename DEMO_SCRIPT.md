# Demo Script

1. Start backend with `cd backend`, `python seed.py`, then `uvicorn app.main:app --reload`.
2. Start frontend with `cd frontend`, `npm run dev`.
3. Open `http://localhost:5173` and sign in as `SOC-AEGIS-001 / security`.
4. Call out KPI tiles: detection rate, FP rate, ATT&CK accuracy, MTTD, MTTR, autonomous playbook percent.
5. Select a high-severity alert and show its ATT&CK technique, confidence, retrieved evidence, and mitigations.
6. Click **Run playbook**. Show low-blast-radius steps execute and endpoint isolation queue for approval.
7. Approve the run and show the audit table hash chain updating.
8. Show the CVE queue ranked by asset criticality, exploitability, and observed TTP overlap.
9. Click **Simulate** in the digital twin and explain that it is model-only.
10. Switch briefly to candidate login and make a failed login; return to SOC and show ingestion if a new alert is raised.

