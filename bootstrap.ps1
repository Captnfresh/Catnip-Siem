# =============================================================
# Catnip Games SIEM - Bootstrap Script (Windows PowerShell)
# Supports: Windows PowerShell 5.1+ with Docker Desktop
# Usage: .\bootstrap.ps1
# =============================================================

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "[..] $msg" -ForegroundColor Yellow }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }
function Write-Step($msg) { Write-Host "`n$msg" -ForegroundColor Cyan }

# Robust .env variable reader — handles CRLF, quotes, and whitespace
function Read-EnvVar($varName, $envFile) {
    $line = Get-Content $envFile | Where-Object { $_ -match "^${varName}=" } | Select-Object -First 1
    if ($line) {
        $value = ($line -replace "^${varName}=", "").Trim()
        # Strip trailing \r (CRLF), leading/trailing quotes
        $value = $value -replace "`r$", ""
        $value = $value.Trim('"').Trim("'")
        return $value
    }
    return ""
}

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
$GRAYLOG_URL       = "http://localhost:9000"
$GRAYLOG_USER      = "admin"
$CONTENT_PACK_NAME = "Catnip Games SIEM"
$SCRIPT_DIR        = Split-Path -Parent $MyInvocation.MyCommand.Path
$CONTENT_PACK_FILE = Join-Path $SCRIPT_DIR "content-packs\catnip-siem-pack.json"
$SCRIPTS_DIR       = Join-Path $SCRIPT_DIR "scripts"
$LOGS_DIR          = Join-Path $SCRIPT_DIR "logs"
$GENERATOR_LOG     = Join-Path $LOGS_DIR "generator.log"
$envFile           = Join-Path $SCRIPT_DIR ".env"

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
Write-Step "[1/8] Checking dependencies..."

try {
    $dockerVersion = docker --version 2>&1
    Write-Ok "Docker found: $dockerVersion"
} catch {
    Write-Fail "Docker not found. Install Docker Desktop from https://docker.com"
}

try {
    $composeVersion = docker compose version 2>&1
    Write-Ok "Docker Compose found"
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
Write-Step "[2/8] Checking Docker Desktop is running..."

try {
    docker ps 2>&1 | Out-Null
    Write-Ok "Docker Desktop is running"
} catch {
    Write-Fail "Docker Desktop is not running. Please start Docker Desktop and wait for 'Engine running' before running this script."
}

# ─────────────────────────────────────────
# Step 3 — Check .env exists and load password
# ─────────────────────────────────────────
Write-Step "[3/8] Checking environment configuration..."

if (-not (Test-Path $envFile)) {
    Write-Host ""
    Write-Host "[ERROR] .env file not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Please create your .env file first:" -ForegroundColor Yellow
    Write-Host "    copy .env.example .env" -ForegroundColor White
    Write-Host ""
    Write-Host "  Then fill in the values shared with your team via WhatsApp." -ForegroundColor Yellow
    Write-Host "  Required:" -ForegroundColor Yellow
    Write-Host "    GRAYLOG_PASSWORD_SECRET" -ForegroundColor White
    Write-Host "    GRAYLOG_ROOT_PASSWORD_SHA2" -ForegroundColor White
    Write-Host "    GRAYLOG_ADMIN_PASSWORD   (plaintext, for API calls)" -ForegroundColor White
    Write-Host "    OPENSEARCH_ADMIN_PASSWORD" -ForegroundColor White
    Write-Host "    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD" -ForegroundColor White
    Write-Host ""
    exit 1
}
Write-Ok ".env file found"

# Load plaintext admin password from .env
$GRAYLOG_PASS = $env:GRAYLOG_PASS
if (-not $GRAYLOG_PASS) {
    $GRAYLOG_PASS = Read-EnvVar "GRAYLOG_ADMIN_PASSWORD" $envFile
}

if (-not $GRAYLOG_PASS) {
    Write-Host ""
    Write-Host "[ERROR] GRAYLOG_ADMIN_PASSWORD not set in .env" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Add this line to your .env file:" -ForegroundColor Yellow
    Write-Host "    GRAYLOG_ADMIN_PASSWORD=<the plaintext admin password>" -ForegroundColor White
    Write-Host ""
    Write-Host "  This is the plaintext whose SHA256 hash is stored in GRAYLOG_ROOT_PASSWORD_SHA2." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
Write-Ok "Graylog admin credentials loaded from .env"

# Build credential object for REST calls
$secPass = ConvertTo-SecureString $GRAYLOG_PASS -AsPlainText -Force
$cred    = New-Object System.Management.Automation.PSCredential($GRAYLOG_USER, $secPass)
$stdHeaders = @{ "X-Requested-By" = "bootstrap" }

# ─────────────────────────────────────────
# Step 4 — Start Docker stack
# ─────────────────────────────────────────
Write-Step "[4/8] Starting Docker containers..."

Write-Info "Running docker compose up -d..."
Set-Location $SCRIPT_DIR
docker compose up -d

Write-Host ""
Write-Info "Waiting for Graylog to become ready (this takes 1-2 minutes)..."

$retries = 60
$count   = 0
$ready   = $false

while ($count -lt $retries) {
    Start-Sleep -Seconds 3
    $count++
    Write-Host -NoNewline "."

    try {
        $response = Invoke-WebRequest -UseBasicParsing `
            -Uri "$GRAYLOG_URL/api/system/lbstatus" `
            -Credential $cred `
            -TimeoutSec 5 `
            -ErrorAction SilentlyContinue

        if ($response.Content -match "ALIVE") {
            $ready = $true
            break
        }
    } catch { }
}

Write-Host ""

if (-not $ready) {
    Write-Fail "Graylog did not become ready after $($retries * 3) seconds.`nRun: docker compose logs graylog"
}
Write-Ok "Graylog is ready"

# Verify credentials actually work
try {
    $null = Invoke-RestMethod -Uri "$GRAYLOG_URL/api/users" -Credential $cred -Headers $stdHeaders -ErrorAction Stop
    Write-Ok "Graylog authentication verified"
} catch {
    Write-Fail "Graylog authentication failed. Check GRAYLOG_ADMIN_PASSWORD in .env matches the password used to generate GRAYLOG_ROOT_PASSWORD_SHA2."
}

# ─────────────────────────────────────────
# Step 5 — Install content pack (idempotent, robust)
# ─────────────────────────────────────────
Write-Step "[5/8] Installing Graylog content pack..."

function Find-PackIdByName {
    try {
        $packs = Invoke-RestMethod -Uri "$GRAYLOG_URL/api/system/content_packs" -Credential $cred -Headers $stdHeaders
        $match = $packs.content_packs | Where-Object { $_.name -eq $CONTENT_PACK_NAME } | Select-Object -First 1
        if ($match) { return $match.id }
    } catch { }
    return $null
}

$packId = $null

if (-not (Test-Path $CONTENT_PACK_FILE)) {
    Write-Warn "Content pack not found at: $CONTENT_PACK_FILE"
    Write-Host "       Install manually: System -> Content Packs -> Upload" -ForegroundColor Yellow
} else {
    # Step 5a: Upload (skip if already uploaded)
    Write-Info "Checking for existing content pack..."
    $packId = Find-PackIdByName

    if ($packId) {
        Write-Ok "Content pack already uploaded (ID: $packId)"
    } else {
        Write-Info "Uploading content pack..."
        try {
            $packContent = Get-Content $CONTENT_PACK_FILE -Raw
            Invoke-RestMethod `
                -Uri "$GRAYLOG_URL/api/system/content_packs" `
                -Method POST `
                -Credential $cred `
                -Headers $stdHeaders `
                -ContentType "application/json" `
                -Body $packContent | Out-Null
            Write-Ok "Content pack uploaded"
            Start-Sleep -Seconds 1
            $packId = Find-PackIdByName
        } catch {
            Write-Warn "Upload failed: $_"
        }
    }

    # Step 5b: Install (always attempt — Graylog is idempotent on re-install)
    if ($packId) {
        Write-Info "Installing content pack (ID: $packId)..."
        try {
            Invoke-RestMethod `
                -Uri "$GRAYLOG_URL/api/system/content_packs/$packId/1/installations" `
                -Method POST `
                -Credential $cred `
                -Headers $stdHeaders `
                -ContentType "application/json" `
                -Body '{"parameters":{},"comment":"Installed by bootstrap"}' | Out-Null
            Write-Ok "Content pack installed - streams, alerts, dashboards, inputs, notifications restored"
        } catch {
            Write-Warn "Install call returned an error (may already be installed): $_"
        }
    } else {
        Write-Warn "Could not resolve content pack ID - install manually via System -> Content Packs"
    }
}

Start-Sleep -Seconds 3

# Verify at least one input exists
try {
    $inputs = Invoke-RestMethod -Uri "$GRAYLOG_URL/api/system/inputs" -Credential $cred -Headers $stdHeaders
    if ($inputs.total -eq 0) {
        Write-Warn "No Graylog inputs configured - logs will not be ingested."
    } else {
        Write-Ok "$($inputs.total) Graylog input(s) configured"
    }
} catch { }

# ─────────────────────────────────────────
# Step 6 — Start log generator
# ─────────────────────────────────────────
Write-Step "[6/8] Installing Python dependencies and starting log generator..."

try {
    python -m pip install requests --quiet 2>&1 | Out-Null
    Write-Ok "Python requests library installed"
} catch {
    Write-Warn "Could not install requests library. Run manually: pip install requests"
}

if (-not (Test-Path $LOGS_DIR)) {
    New-Item -ItemType Directory -Path $LOGS_DIR | Out-Null
}

# Kill any existing generator
Get-Process -Name "python*" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*log_generator*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue

# Capture baseline via universal search (works across Graylog versions)
function Get-MessageCount {
    try {
        $resp = Invoke-RestMethod `
            -Uri "$GRAYLOG_URL/api/search/universal/relative?query=*&range=300&limit=1" `
            -Credential $cred `
            -Headers $stdHeaders
        return [int]$resp.total_results
    } catch {
        return 0
    }
}

$baselineCount = Get-MessageCount
Write-Info "Baseline message count: $baselineCount"

$generatorScript = Join-Path $SCRIPTS_DIR "log_generator.py"
$process = Start-Process python `
    -ArgumentList $generatorScript `
    -RedirectStandardOutput $GENERATOR_LOG `
    -RedirectStandardError "$LOGS_DIR\generator_error.log" `
    -WindowStyle Hidden `
    -PassThru

Start-Sleep -Seconds 3

if ($process.HasExited) {
    Write-Warn "Log generator crashed on startup. Last 20 lines of generator log:"
    Write-Host "---" -ForegroundColor Gray
    if (Test-Path $GENERATOR_LOG) { Get-Content $GENERATOR_LOG -Tail 20 }
    if (Test-Path "$LOGS_DIR\generator_error.log") { Get-Content "$LOGS_DIR\generator_error.log" -Tail 20 }
    Write-Host "---" -ForegroundColor Gray
    Write-Fail "Cannot continue - fix the generator and re-run bootstrap."
}
Write-Ok "Log generator running (PID: $($process.Id))"

# ─────────────────────────────────────────
# Step 7 — Smoke test: verify logs are flowing
# ─────────────────────────────────────────
Write-Step "[7/8] Verifying end-to-end log flow..."

$smokeRetries = 10
$smokeCount   = 0
$logsFlowing  = $false

while ($smokeCount -lt $smokeRetries) {
    Start-Sleep -Seconds 3
    $currentCount = Get-MessageCount

    if ($currentCount -gt $baselineCount) {
        $newMessages = $currentCount - $baselineCount
        Write-Ok "Logs flowing: $newMessages new messages ingested (total: $currentCount)"
        $logsFlowing = $true
        break
    }

    $smokeCount++
    Write-Host -NoNewline "."
}
Write-Host ""

if (-not $logsFlowing) {
    Write-Warn "No new messages detected after 30 seconds. Possible causes:"
    Write-Host "       - Content pack inputs not started - check System -> Inputs in Graylog UI"
    Write-Host "       - Log generator sending to wrong port - check: Get-Content $GENERATOR_LOG"
    Write-Host "       - Firewall blocking localhost:1514 or localhost:12201"
    Write-Host ""
    Write-Host "       Last 10 lines of generator log:"
    Write-Host "       ---" -ForegroundColor Gray
    if (Test-Path $GENERATOR_LOG) { Get-Content $GENERATOR_LOG -Tail 10 | ForEach-Object { "       $_" } }
    Write-Host "       ---" -ForegroundColor Gray
}

# ─────────────────────────────────────────
# Step 8 — Start OmniLog AI assistant
# ─────────────────────────────────────────
Write-Step "[8/8] Starting OmniLog AI assistant..."

$mlLog       = Join-Path $LOGS_DIR "ml_service.log"
$apiLog      = Join-Path $LOGS_DIR "omnilog_api.log"
$uiLog       = Join-Path $LOGS_DIR "omnilog_ui.log"
$omnilogDir  = Join-Path $SCRIPT_DIR "omnilog"
$requirementsFile = Join-Path $SCRIPT_DIR "ml\requirements.txt"

Write-Info "Installing OmniLog Python dependencies..."
try {
    python -m pip install -r $requirementsFile --quiet 2>&1 | Out-Null
    Write-Ok "OmniLog Python dependencies ready"
} catch {
    Write-Warn "Could not install OmniLog deps. Run manually: pip install -r ml\requirements.txt"
}

# Check model file
$modelFile = Join-Path $SCRIPT_DIR "models\catnip_severity_model.pkl"
$mlSkip = $false
if (-not (Test-Path $modelFile)) {
    Write-Warn "ML model not found: $modelFile"
    Write-Host "       Skipping ML service — train in notebooks\catnip_ml_trainer.ipynb and copy the .pkl to models\" -ForegroundColor Yellow
    $mlSkip = $true
} else {
    Write-Ok "ML model found"
}

# Kill any stale instances
Get-Process python* -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match "ml_service|omnilog_api" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

if (-not $mlSkip) {
    Write-Info "Starting ML service (port 5001)..."
    $mlProcess = Start-Process python `
        -ArgumentList (Join-Path $SCRIPTS_DIR "ml_service.py") `
        -RedirectStandardOutput $mlLog `
        -RedirectStandardError "$LOGS_DIR\ml_service_error.log" `
        -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 3
    if (-not $mlProcess.HasExited) {
        Write-Ok "ML service running (PID: $($mlProcess.Id))"
    } else {
        Write-Warn "ML service failed to start. Check: $mlLog"
    }
}

Write-Info "Starting OmniLog API (port 5002)..."
$apiProcess = Start-Process python `
    -ArgumentList (Join-Path $SCRIPTS_DIR "omnilog_api.py") `
    -RedirectStandardOutput $apiLog `
    -RedirectStandardError "$LOGS_DIR\omnilog_api_error.log" `
    -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 3
if (-not $apiProcess.HasExited) {
    Write-Ok "OmniLog API running (PID: $($apiProcess.Id))"
} else {
    Write-Warn "OmniLog API failed to start. Check: $apiLog"
}

$omnilogUiPid = $null
try {
    $nodeVersion = node --version 2>&1
    if (Test-Path $omnilogDir) {
        if (-not (Test-Path (Join-Path $omnilogDir "node_modules"))) {
            Write-Info "Installing OmniLog frontend dependencies (first run)..."
            Push-Location $omnilogDir
            npm install --silent 2>&1 | Out-Null
            Pop-Location
        }
        Write-Info "Starting OmniLog frontend (port 5173)..."
        $viteBin = Join-Path $omnilogDir "node_modules\.bin\vite.cmd"
        $cmdArgs = "/c cd /d `"$omnilogDir`" & node_modules\.bin\vite --port 5173"
        $uiProcess = Start-Process "cmd.exe" -ArgumentList $cmdArgs -RedirectStandardOutput $uiLog -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 4
        if (-not $uiProcess.HasExited) {
            $omnilogUiPid = $uiProcess.Id
            Write-Ok "OmniLog UI running (PID: $omnilogUiPid) — http://localhost:5173"
        } else {
            Write-Warn "OmniLog UI failed to start. Check: $uiLog"
        }
    }
} catch {
    Write-Warn "Node.js not found — skipping OmniLog frontend. Install from https://nodejs.org"
}

# ─────────────────────────────────────────
# Done
# ─────────────────────────────────────────
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Green
if ($logsFlowing) {
    Write-Host "   Bootstrap complete - SIEM is fully operational!" -ForegroundColor Green
} else {
    Write-Host "   Bootstrap complete - but verify logs manually." -ForegroundColor Yellow
}
Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Graylog UI:    $GRAYLOG_URL"
Write-Host "  Username:      admin"
Write-Host "  Password:      (from GRAYLOG_ADMIN_PASSWORD in .env)"
Write-Host "  Attack Map:    http://localhost:8888"
Write-Host "  OmniLog UI:    http://localhost:5173"
Write-Host "  OmniLog API:   http://localhost:5002"
Write-Host "  ML Service:    http://localhost:5001"
Write-Host ""
Write-Host "  Log generator: running in background (PID: $($process.Id))"
Write-Host "  Generator log: $GENERATOR_LOG"
Write-Host ""
Write-Host "  To generate a security report:"
Write-Host "    python scripts\report_generator.py"
Write-Host ""
Write-Host "  To stop everything:"
Write-Host "    Stop-Process -Name python -Force"
Write-Host "    docker compose down"
Write-Host ""
Write-Host "============================================================="
Write-Host ""
