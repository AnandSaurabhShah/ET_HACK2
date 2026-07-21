param(
  [string]$ModelName = "aegis-cni:latest",
  [string]$BaseModel = "llama3.2:latest"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$modelfile = Join-Path $root "ollama\Modelfile"

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
  throw "Ollama CLI not found. Install Ollama, start it, then re-run this script."
}

if (-not (Test-Path $modelfile)) {
  throw "Missing Modelfile at $modelfile"
}

Write-Host "Pulling base model $BaseModel if needed..."
ollama pull $BaseModel

Write-Host "Creating $ModelName from $modelfile..."
ollama create $ModelName -f $modelfile

Write-Host ""
Write-Host "Created $ModelName"
Write-Host "Set backend/.env:"
Write-Host "AEGIS_GENAI_PROVIDER=ollama"
Write-Host "AEGIS_GENAI_ENDPOINT=http://127.0.0.1:11434/api/generate"
Write-Host "AEGIS_GENAI_MODEL=$ModelName"
