$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Python environment missing. Run the two setup commands in README.md first."
}
if (-not (Test-Path (Join-Path $root "frontend\node_modules"))) {
    throw "Frontend dependencies missing. Run npm install in the frontend folder first."
}

$apiCommand = "& '$python' -m uvicorn backend.server:app --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $apiCommand -WorkingDirectory $root

Write-Host "Starting Sentinel dashboard. Keep both PowerShell windows open while using the application."
Push-Location (Join-Path $root "frontend")
try {
    npm run dev
} finally {
    Pop-Location
}
