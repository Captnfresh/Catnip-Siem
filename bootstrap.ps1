# =============================================================
# Catnip Games SIEM - Bootstrap Script (Windows PowerShell)
# Supports: Windows PowerShell 5.1+ with Docker Desktop
# Usage: Right-click → Run with PowerShell
#        OR in PowerShell: .\bootstrap.ps1
# =============================================================

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "[..] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }
function Write-Step($msg) { Write-Host "`n$msg" -ForegroundColor Cyan }

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
$GRAYLOG_URL       = "http://localhost:9000"
$GRAYLOG_USER      = "admin"
$SCRIPT_DIR        = Split-Path -Parent $MyInvocation.MyCommand.Path
$CONTENT_PACK_FILE = Join-Path $SCRIPT_DIR "content-packs\catnip-siem-pack.json"
$SCRIPTS_DIR       = Join-Path $SCRIPT_DIR "scripts"
$LOGS_DIR          = Join-Path $SCRIPT_DIR "logs"
$GENERATOR_LOG     = Join-Path $LOGS_DIR "generator.log"

# ─────────────────────────────────────────
# Header
# ─────────────────────────────────────────
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "   Catnip Games International - SIEM Bootstrap (PowerShell)" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────
# Step 1 — Check dependencies
# ─────────────────────────────────────────
Write-Step "[1/6] Checking dependencies..."

try {
    $dockerVersion = docker --version 2>&1
    Write-Ok "Docker found: $dockerVersion"
} catch {
    Write-Fail "Docker not found. Install Docker Desktop from https://docker.com"
}

try {
    $composeVersion = docker compose version 2>&1
    Write-Ok "Docker Compose found: $composeVersion"
} catch {
    Write-Fail "Docker Compose not found. Please update Docker Desktop."
}

try {
    $pythonVersion = python --version 2>&1
    if (-not $pythonVersion) { $pythonVersion = python3 --version 2>&1 }
    Write-Ok "Python found: $pythonVersion"
} catch {
    Write-Fail "Python not found. Install Python 3 from https://python.org"
}

# ─────────────────────────────────────────
# Step 2 — Check Docker Desktop is running
# ─────────────────────────────────────────
Write-Step "[2/6] Checking Docker Desktop is running..."

$dockerRunning = $false
try {
    docker ps 2>&1 | Out-Null
    $dockerRunning = $true
    Write-Ok "Docker Desktop is running"
} catch {
    Write-Fail "Docker Desktop is not running. Please start Docker Desktop and wait for 'Engine running' before running this script."
}

# ─────────────────────────────────────────
# Step 3 — Check .env exists
# ─────────────────────────────────────────
Write-Step "[3/6] Checking environment configuration..."

$envFile = Join-Path $SCRIPT_DIR ".env"
if (-not (Test-Path $envFile)) {
    Write-Host ""
    Write-Host "[ERROR] .env file not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Please create your .env file first:" -ForegroundColor Yellow
    Write-Host "    copy .env.example .env" -ForegroundColor White
    Write-Host ""
    Write-Host "  Then fill in the values shared with your team via WhatsApp." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
Write-Ok ".env file found"

# Read admin password for API calls
$GRAYLOG_PASS = $env:GRAYLOG_PASS
if (-not $GRAYLOG_PASS) {
    Write-Host ""
    $GRAYLOG_PASS = Read-Host "Enter your Graylog admin password (for API calls)" -AsSecureString
    $GRAYLOG_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($GRAYLOG_PASS)
    )
}

# ─────────────────────────────────────────
# Step 4 — Start Docker stack
# ─────────────────────────────────────────
Write-Step "[4/6] Starting Docker containers..."

Write-Info "Running docker compose up -d..."
Set-Location $SCRIPT_DIR
docker compose up -d

Write-Host ""
Write-Info "Waiting for Graylog to become healthy (this takes 1-2 minutes)..."

$retries = 60
$count   = 0
$healthy = $false

while ($count -lt $retries) {
    Start-Sleep -Seconds 3
    $count++
    Write-Host -NoNewline "."

    try {
        $response = Invoke-RestMethod `
            -Uri "$GRAYLOG_URL/api/system/lbstatus" `
            -Headers @{ Accept = "application/json" } `
            -Credential (New-Object System.Management.Automation.PSCredential(
                $GRAYLOG_USER,
                (ConvertTo-SecureString $GRAYLOG_PASS -AsPlainText -Force)
            )) `
            -ErrorAction SilentlyContinue

        if ($response -match "ALIVE" -or $response.status -eq "ALIVE") {
            $healthy = $true
            break
        }
    } catch { }
}

Write-Host ""

if (-not $healthy) {
    Write-Fail "Graylog did not become healthy after $($retries * 3) seconds.`nRun: docker compose logs graylog"
}
Write-Ok "Graylog is healthy"

# ─────────────────────────────────────────
# Step 5 — Install content pack
# ─────────────────────────────────────────
Write-Step "[5/6] Installing Graylog content pack..."

$cred = New-Object System.Management.Automation.PSCredential(
    $GRAYLOG_USER,
    (ConvertTo-SecureString $GRAYLOG_PASS -AsPlainText -Force)
)

if (-not (Test-Path $CONTENT_PACK_FILE)) {
    Write-Host "[SKIP] Content pack not found at: $CONTENT_PACK_FILE" -ForegroundColor Yellow
    Write-Host "       Install manually: System -> Content Packs -> Upload" -ForegroundColor Yellow
} else {
    Write-Info "Uploading content pack to Graylog API..."

    try {
        $packContent = Get-Content $CONTENT_PACK_FILE -Raw

        $uploadResponse = Invoke-RestMethod `
            -Uri "$GRAYLOG_URL/api/system/content_packs" `
            -Method POST `
            -Credential $cred `
            -Headers @{ "X-Requested-By" = "bootstrap" } `
            -ContentType "application/json" `
            -Body $packContent

        $packId = $uploadResponse.id
        if (-not $packId) { $packId = $uploadResponse.content_pack_id }

        Write-Ok "Content pack uploaded (ID: $packId)"

        Write-Info "Installing content pack..."
        $installResponse = Invoke-RestMethod `
            -Uri "$GRAYLOG_URL/api/system/content_packs/$packId/1/installations" `
            -Method POST `
            -Credential $cred `
            -Headers @{ "X-Requested-By" = "bootstrap" } `
            -ContentType "application/json" `
            -Body '{"parameters":{},"comment":"Installed by bootstrap script"}'

        Write-Ok "Content pack installed — streams, alerts, dashboards, notifications restored"

    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 400) {
            Write-Host "[SKIP] Content pack already exists in Graylog" -ForegroundColor Yellow
            Write-Ok "Skipping — content pack already installed"
        } else {
            Write-Host "[WARN] Content pack installation failed: $_" -ForegroundColor Yellow
            Write-Host "       Install manually: System -> Content Packs -> Upload" -ForegroundColor Yellow
        }
    }
}

# ─────────────────────────────────────────
# Step 6 — Install Python deps + start generator
# ─────────────────────────────────────────
Write-Step "[6/6] Installing Python dependencies and starting log generator..."

try {
    python -m pip install requests --quiet 2>&1 | Out-Null
    Write-Ok "Python requests library installed"
} catch {
    Write-Host "[WARN] Could not install requests library. Run manually: pip install requests" -ForegroundColor Yellow
}

if (-not (Test-Path $LOGS_DIR)) {
    New-Item -ItemType Directory -Path $LOGS_DIR | Out-Null
}

# Kill any existing generator
Get-Process -Name "python*" -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowTitle -like "*log_generator*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue

$generatorScript = Join-Path $SCRIPTS_DIR "log_generator.py"
$process = Start-Process python `
    -ArgumentList $generatorScript `
    -RedirectStandardOutput $GENERATOR_LOG `
    -RedirectStandardError "$LOGS_DIR\generator_error.log" `
    -WindowStyle Hidden `
    -PassThru

Start-Sleep -Seconds 2

if ($process -and -not $process.HasExited) {
    Write-Ok "Log generator started (PID: $($process.Id))"
} else {
    Write-Host "[WARN] Log generator may not have started. Check: $GENERATOR_LOG" -ForegroundColor Yellow
}

# ─────────────────────────────────────────
# Done
# ─────────────────────────────────────────
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Green
Write-Host "   Bootstrap complete!" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Graylog UI:    $GRAYLOG_URL"
Write-Host "  Username:      admin"
Write-Host "  Password:      (from your .env file)"
Write-Host ""
Write-Host "  Log generator: running in background (PID: $($process.Id))"
Write-Host "  Generator log: $GENERATOR_LOG"
Write-Host ""
Write-Host "  To generate a security report:"
Write-Host "    `$env:GRAYLOG_PASS = 'your_password'"
Write-Host "    python scripts\report_generator.py"
Write-Host ""
Write-Host "  To stop all containers:"
Write-Host "    docker compose down"
Write-Host ""
Write-Host "============================================================="
Write-Host ""
