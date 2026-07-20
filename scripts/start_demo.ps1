param(
  [int]$BackendPort = 8000,
  [int]$FrontendPort = 5173
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"

Write-Host "== Aegis-CNI Demo Boot =="
Write-Host "1) Installing backend requirements"
Push-Location $Backend
python -m pip install -r requirements.txt

Write-Host "2) Seeding telemetry, MITRE corpus, NVD CVE cache, eval report, and SQL mirror"
python seed.py

Write-Host "3) Starting backend on http://127.0.0.1:$BackendPort"
$backendLog = Join-Path $Backend "backend-uvicorn.log"
$backendErr = Join-Path $Backend "backend-uvicorn.err.log"
Start-Process -FilePath python -ArgumentList @("-m","uvicorn","app.main:app","--reload","--host","127.0.0.1","--port", "$BackendPort") -WorkingDirectory $Backend -WindowStyle Hidden -RedirectStandardOutput $backendLog -RedirectStandardError $backendErr | Out-Null
Pop-Location

Write-Host "4) Installing frontend dependencies"
Push-Location $Frontend
if (-not (Test-Path ".env")) {
  "VITE_AEGIS_API_URL=http://127.0.0.1:$BackendPort" | Set-Content -Encoding UTF8 ".env"
}
npm install

Write-Host "5) Starting frontend on http://127.0.0.1:$FrontendPort"
$frontendLog = Join-Path $Frontend "frontend-vite.log"
$frontendErr = Join-Path $Frontend "frontend-vite.err.log"
$npm = (Get-Command npm.cmd).Source
Start-Process -FilePath $npm -ArgumentList @("run","dev","--","--host","127.0.0.1","--port", "$FrontendPort") -WorkingDirectory $Frontend -WindowStyle Hidden -RedirectStandardOutput $frontendLog -RedirectStandardError $frontendErr | Out-Null
Pop-Location

Start-Sleep -Seconds 5

Write-Host ""
Write-Host "== Smoke Checks =="
try {
  Invoke-RestMethod -Uri "http://127.0.0.1:$BackendPort/health" -TimeoutSec 10 | ConvertTo-Json
  Invoke-RestMethod -Uri "http://127.0.0.1:$BackendPort/eval/report" -TimeoutSec 10 | Select-Object detection_rate,false_positive_rate,attack_technique_accuracy,mitre_technique_count | ConvertTo-Json
  $status = (Invoke-WebRequest -Uri "http://127.0.0.1:$FrontendPort" -UseBasicParsing -TimeoutSec 10).StatusCode
  Write-Host "Frontend HTTP status: $status"
} catch {
  Write-Host "Smoke check failed: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "== Demo Script =="
Write-Host "1. Open http://127.0.0.1:$FrontendPort"
Write-Host "2. Login as SOC-AEGIS-001 / security"
Write-Host "3. Click 'Simulate T1110' in the SOC dashboard and watch SSE alerts appear"
Write-Host "4. Or run: cd backend; python tools/attack_simulator.py --technique T1110 --count 8"
Write-Host "5. Run a playbook, approve queued high-blast-radius action, then show /audit/verify"
Write-Host "6. Show the CVE queue source column: nvd_live, cached, or static_fallback"

