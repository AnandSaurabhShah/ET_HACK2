# Live Perimeter Detection Testing

These checks hit the actual running FastAPI backend. They do not use the Simulate button or `attack_simulator.py`.

Start the stack:

```powershell
cd backend
python seed.py
uvicorn app.main:app --reload --port 8000
```

In another terminal:

```powershell
cd frontend
npm run dev
```

Open `http://127.0.0.1:5173`, sign in as `SOC-AEGIS-001 / security`, and watch for `Perimeter` badges in the alert feed.
The live alert feed should be empty until one of these real HTTP requests is sent.

## SQL Injection Shape

Use `X-Forwarded-For` so you only block the test IP, not your browser at `127.0.0.1`.

```powershell
curl.exe -H "X-Forwarded-For: 198.51.100.77" "http://127.0.0.1:8000/health?q=' OR '1'='1"
curl.exe -H "X-Forwarded-For: 198.51.100.77" "http://127.0.0.1:8000/health"
```

Expected:

- First request is detected as `sqli_attempt`, mapped to `T1190`, and blocked.
- Second request from the same test IP returns HTTP `403`.

## Command Injection Shape

```powershell
curl.exe -H "X-Forwarded-For: 198.51.100.78" "http://127.0.0.1:8000/health?cmd=;whoami"
curl.exe -H "X-Forwarded-For: 198.51.100.78" "http://127.0.0.1:8000/ready"
```

Expected:

- `command_injection_attempt`, mapped to `T1059`.
- Follow-up request returns `403`.

## Path Traversal Shape

```powershell
curl.exe -H "X-Forwarded-For: 198.51.100.79" "http://127.0.0.1:8000/health?file=..%2f..%2fWindows%2fwin.ini"
curl.exe -H "X-Forwarded-For: 198.51.100.79" "http://127.0.0.1:8000/health"
```

Expected:

- `path_traversal_attempt`, mapped to `T1083`.
- Follow-up request returns `403`.

## XSS Shape

```powershell
curl.exe -H "X-Forwarded-For: 198.51.100.80" "http://127.0.0.1:8000/health?x=%3Cscript%3Ealert(1)%3C/script%3E"
curl.exe -H "X-Forwarded-For: 198.51.100.80" "http://127.0.0.1:8000/health"
```

Expected:

- `xss_attempt`, mapped to `T1189`.
- Follow-up request returns `403`.

## Scanner User-Agent As Supporting Signal

Scanner User-Agent alone should not block, because User-Agent is spoofable:

```powershell
curl.exe -H "X-Forwarded-For: 198.51.100.81" -A "sqlmap/1.8" "http://127.0.0.1:8000/health"
```

Expected:

- No immediate block from User-Agent alone.

## Endpoint Enumeration / Scan Burst

```powershell
1..30 | ForEach-Object {
  curl.exe -s -o NUL -H "X-Forwarded-For: 198.51.100.82" "http://127.0.0.1:8000/probe-$_"
}
curl.exe -i -H "X-Forwarded-For: 198.51.100.82" "http://127.0.0.1:8000/health"
```

Expected:

- `scan_burst`, mapped to `T1595`, after distinct endpoint threshold is crossed.
- Follow-up request returns `403`.

## Failed Login / Brute Force

```powershell
1..8 | ForEach-Object {
  $body = @{
    user_id = "CAND-2026-004821"
    role = "candidate"
    event_type = "login"
    success = $false
    latency_ms = 230
    bytes_out = 8
  } | ConvertTo-Json -Compress
  try {
    Invoke-WebRequest -Method Post -Uri "http://127.0.0.1:8000/ingest/events" `
      -Headers @{ "X-Forwarded-For" = "198.51.100.83"; "Content-Type" = "application/json" } `
      -Body $body -UseBasicParsing | Out-Null
  } catch {
    "Blocked on attempt $_"
  }
}
curl.exe -i -H "X-Forwarded-For: 198.51.100.83" "http://127.0.0.1:8000/health"
```

Expected:

- `brute_force_attempt`, mapped to `T1110`.
- Follow-up request returns `403`.

## Verify Audit And Blocklist Evidence

```powershell
curl.exe "http://127.0.0.1:8000/audit/verify"
curl.exe "http://127.0.0.1:8000/ready"
```

Expected:

- `/audit/verify` returns `"ok": true`.
- `/ready` includes active `blocked_ips` until cooldown expiry.
