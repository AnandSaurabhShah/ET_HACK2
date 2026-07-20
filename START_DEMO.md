# One-Command Demo Start

From the repository root:

```powershell
.\scripts\start_demo.ps1
```

The script runs:

1. `pip install -r requirements.txt`
2. `python seed.py`
3. `uvicorn app.main:app --reload --port 8000`
4. `npm install`
5. `npm run dev`
6. Smoke checks for `/health`, `/eval/report`, and the frontend.

Demo path:

1. Open `http://127.0.0.1:5173`.
2. Login as `SOC-AEGIS-001 / security`.
3. Click **Simulate T1110** in the SOC dashboard.
4. Watch live SSE alerts appear.
5. Run a playbook and approve any queued high-blast-radius action.
6. Show `http://127.0.0.1:8000/audit/verify`.

