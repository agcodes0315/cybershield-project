$ErrorActionPreference = "Stop"

$root = "C:\Users\Lenovo\Desktop\Cybershield Project"

$detectionEngine = Join-Path $root "detection-engine"
$apiGateway = Join-Path $root "api-gateway"
$client = Join-Path $root "client"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       CYBERSHIELD PROJECT STARTUP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

function Test-RequiredPath {
    param(
        [string]$Path,
        [string]$Name
    )

    if (-not (Test-Path $Path)) {
        Write-Host "[ERROR] $Name was not found:" -ForegroundColor Red
        Write-Host "        $Path" -ForegroundColor Red
        exit 1
    }

    Write-Host "[OK] $Name found" -ForegroundColor Green
}

function Test-Port {
    param(
        [int]$Port
    )

    return [bool](
        Get-NetTCPConnection `
            -LocalPort $Port `
            -State Listen `
            -ErrorAction SilentlyContinue
    )
}

Test-RequiredPath $detectionEngine "Detection engine"
Test-RequiredPath $apiGateway "API gateway"
Test-RequiredPath $client "React client"

Test-RequiredPath `
    (Join-Path $apiGateway "package.json") `
    "API gateway package.json"

Test-RequiredPath `
    (Join-Path $client "package.json") `
    "React client package.json"

Write-Host ""
Write-Host "Starting Docker services..." -ForegroundColor Yellow

Set-Location $root

try {
    docker compose up -d
    Write-Host "[OK] Docker services started" -ForegroundColor Green
}
catch {
    Write-Host "[WARNING] Docker could not be started automatically." -ForegroundColor Yellow
    Write-Host "Make sure Docker Desktop is running." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Starting detection engine on port 8000..." -ForegroundColor Yellow

$detectionCommand = @"
Set-Location '$detectionEngine'
`$Host.UI.RawUI.WindowTitle = 'CyberShield - Detection Engine'

if (Test-Path '.venv\Scripts\Activate.ps1') {
    & '.\.venv\Scripts\Activate.ps1'
}
elseif (Test-Path 'venv\Scripts\Activate.ps1') {
    & '.\venv\Scripts\Activate.ps1'
}

Write-Host 'Starting FastAPI detection engine...' -ForegroundColor Cyan
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
"@

Start-Process powershell `
    -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $detectionCommand

Write-Host "Starting API gateway on port 5000..." -ForegroundColor Yellow

$gatewayCommand = @"
Set-Location '$apiGateway'
`$Host.UI.RawUI.WindowTitle = 'CyberShield - API Gateway'

if (-not (Test-Path 'node_modules')) {
    Write-Host 'Installing API gateway dependencies...' -ForegroundColor Yellow
    npm install
}

Write-Host 'Starting Node API gateway...' -ForegroundColor Cyan
npm run dev
"@

Start-Process powershell `
    -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $gatewayCommand

Write-Host "Starting React client on port 5173..." -ForegroundColor Yellow

$clientCommand = @"
Set-Location '$client'
`$Host.UI.RawUI.WindowTitle = 'CyberShield - React Client'

if (-not (Test-Path 'node_modules')) {
    Write-Host 'Installing React dependencies...' -ForegroundColor Yellow
    npm install
}

Write-Host 'Starting Vite frontend...' -ForegroundColor Cyan
npm run dev
"@

Start-Process powershell `
    -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $clientCommand

Write-Host ""
Write-Host "Waiting for services..." -ForegroundColor Yellow

$maximumAttempts = 40
$attempt = 0

while ($attempt -lt $maximumAttempts) {
    $frontendReady = Test-Port 5173
    $gatewayReady = Test-Port 5000
    $engineReady = Test-Port 8000

    Write-Host `
        "Frontend: $frontendReady | Gateway: $gatewayReady | Engine: $engineReady"

    if ($frontendReady -and $gatewayReady -and $engineReady) {
        break
    }

    Start-Sleep -Seconds 2
    $attempt++
}

Write-Host ""

if (Test-Port 8000) {
    Write-Host "[OK] Detection engine: http://127.0.0.1:8000" -ForegroundColor Green
}
else {
    Write-Host "[FAILED] Detection engine did not start on port 8000" -ForegroundColor Red
}

if (Test-Port 5000) {
    Write-Host "[OK] API gateway: http://127.0.0.1:5000" -ForegroundColor Green
}
else {
    Write-Host "[FAILED] API gateway did not start on port 5000" -ForegroundColor Red
}

if (Test-Port 5173) {
    Write-Host "[OK] Frontend: http://127.0.0.1:5173" -ForegroundColor Green
}
else {
    Write-Host "[FAILED] Frontend did not start on port 5173" -ForegroundColor Red
}

if (
    (Test-Port 5173) -and
    (Test-Port 5000) -and
    (Test-Port 8000)
) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "       ALL SERVICES ARE RUNNING" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green

    Start-Process "http://127.0.0.1:5173"
}
else {
    Write-Host ""
    Write-Host "One or more services failed to start." -ForegroundColor Red
    Write-Host "Check the three opened PowerShell windows for the exact error." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press Enter to close this launcher window." -ForegroundColor Gray
Read-Host