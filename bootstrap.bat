@echo off
REM =============================================================
REM Catnip Games SIEM - Bootstrap Script (Windows CMD)
REM Supports: Windows Command Prompt with Docker Desktop
REM Usage: Double-click bootstrap.bat  OR  in CMD: bootstrap.bat
REM =============================================================

setlocal EnableDelayedExpansion
title Catnip Games SIEM - Bootstrap

echo.
echo =============================================================
echo    Catnip Games International - SIEM Bootstrap (Windows)
echo =============================================================
echo.

REM ─────────────────────────────────────────
REM Step 1 - Check dependencies
REM ─────────────────────────────────────────
echo [1/8] Checking dependencies...
echo.

docker --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker not found.
    echo         Please install Docker Desktop from https://docker.com
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('docker --version') do echo [OK] %%v

docker compose version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker Compose not found. Please update Docker Desktop.
    pause
    exit /b 1
)
echo [OK] Docker Compose found

python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found.
    echo         Please install Python 3 from https://python.org
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version') do echo [OK] %%v

REM ─────────────────────────────────────────
REM Step 2 - Check Docker is running
REM ─────────────────────────────────────────
echo.
echo [2/8] Checking Docker Desktop is running...
echo.

docker ps >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker Desktop is not running.
    echo         Please start Docker Desktop and wait for "Engine running".
    pause
    exit /b 1
)
echo [OK] Docker Desktop is running

REM ─────────────────────────────────────────
REM Step 3 - Check .env and load password
REM ─────────────────────────────────────────
echo.
echo [3/8] Checking environment configuration...
echo.

if not exist ".env" (
    echo [ERROR] .env file not found.
    echo.
    echo   Please create your .env file first:
    echo     copy .env.example .env
    echo.
    echo   Then fill in the values shared with your team via WhatsApp.
    echo   Required:
    echo     GRAYLOG_PASSWORD_SECRET
    echo     GRAYLOG_ROOT_PASSWORD_SHA2
    echo     GRAYLOG_ADMIN_PASSWORD   (plaintext, for API calls)
    echo     OPENSEARCH_ADMIN_PASSWORD
    echo     SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
    echo.
    pause
    exit /b 1
)
echo [OK] .env file found

REM Load GRAYLOG_ADMIN_PASSWORD from .env — strip whitespace and CR (trailing \r from CRLF)
if "%GRAYLOG_PASS%"=="" (
    for /f "tokens=*" %%i in ('python -c "import re; [print(l.split('=',1)[1].rstrip()) for l in open('.env') if re.match(r'^GRAYLOG_ADMIN_PASSWORD=', l)]" 2^>nul') do set "GRAYLOG_PASS=%%i"
)

if "%GRAYLOG_PASS%"=="" (
    echo.
    echo [ERROR] GRAYLOG_ADMIN_PASSWORD not set in .env
    echo.
    echo   Add this line to your .env file:
    echo     GRAYLOG_ADMIN_PASSWORD=the plaintext admin password
    echo.
    echo   This is the plaintext whose SHA256 hash is stored in
    echo   GRAYLOG_ROOT_PASSWORD_SHA2.
    echo.
    pause
    exit /b 1
)
echo [OK] Graylog admin credentials loaded from .env

REM ─────────────────────────────────────────
REM Step 4 - Start Docker stack
REM ─────────────────────────────────────────
echo.
echo [4/8] Starting Docker containers...
echo.

docker compose up -d
if %ERRORLEVEL% neq 0 (
    echo [ERROR] docker compose up failed.
    pause
    exit /b 1
)

echo.
echo [..] Waiting for Graylog to become ready (1-2 minutes)...
echo.

set RETRIES=60
set COUNT=0

:WAIT_LOOP
if %COUNT% geq %RETRIES% goto TIMEOUT
set /a COUNT+=1
<nul set /p ".=."
timeout /t 3 /nobreak >nul 2>&1

curl -s -u "admin:%GRAYLOG_PASS%" ^
    http://localhost:9000/api/system/lbstatus 2>nul | find "ALIVE" >nul 2>&1
if %ERRORLEVEL% equ 0 goto READY
goto WAIT_LOOP

:TIMEOUT
echo.
echo [ERROR] Graylog did not become ready in time.
echo         Run: docker compose logs graylog
pause
exit /b 1

:READY
echo.
echo [OK] Graylog is ready

REM Verify auth works
curl -s -o nul -w "%%{http_code}" -u "admin:%GRAYLOG_PASS%" ^
    http://localhost:9000/api/users > temp_auth.txt 2>nul
set /p AUTH_CODE=<temp_auth.txt
del temp_auth.txt 2>nul
if not "%AUTH_CODE%"=="200" (
    echo [ERROR] Graylog authentication failed ^(HTTP %AUTH_CODE%^).
    echo         Check GRAYLOG_ADMIN_PASSWORD matches the password used
    echo         to generate GRAYLOG_ROOT_PASSWORD_SHA2.
    pause
    exit /b 1
)
echo [OK] Graylog authentication verified

REM ─────────────────────────────────────────
REM Step 5 - Install content pack
REM ─────────────────────────────────────────
echo.
echo [5/8] Installing Graylog content pack...
echo.

set CONTENT_PACK=content-packs\catnip-siem-pack.json
set CONTENT_PACK_NAME=Catnip Games SIEM

if not exist "%CONTENT_PACK%" (
    echo [SKIP] Content pack not found at: %CONTENT_PACK%
    echo        Install manually: System -^> Content Packs -^> Upload
    goto SKIP_CONTENT_PACK
)

REM Step 5a: Check if already uploaded
echo [..] Checking for existing content pack...
curl -s -u "admin:%GRAYLOG_PASS%" -H "X-Requested-By: bootstrap" ^
    http://localhost:9000/api/system/content_packs > temp_packs.json 2>nul
for /f "tokens=*" %%i in ('python -c "import json; packs=json.load(open('temp_packs.json'))['content_packs']; print(next((p['id'] for p in packs if p.get('name')=='%CONTENT_PACK_NAME%'), ''))" 2^>nul') do set PACK_ID=%%i
del temp_packs.json 2>nul

if not "%PACK_ID%"=="" (
    echo [OK] Content pack already uploaded ^(ID: %PACK_ID%^)
    goto INSTALL_PACK
)

REM Step 5b: Upload if not present
echo [..] Uploading content pack...
curl -s -o nul -w "%%{http_code}" ^
    -u "admin:%GRAYLOG_PASS%" ^
    -H "X-Requested-By: bootstrap" ^
    -H "Content-Type: application/json" ^
    -X POST ^
    http://localhost:9000/api/system/content_packs ^
    -d @"%CONTENT_PACK%" > temp_http.txt 2>nul
set /p UPLOAD_CODE=<temp_http.txt
del temp_http.txt 2>nul

if not "%UPLOAD_CODE%"=="200" if not "%UPLOAD_CODE%"=="201" (
    echo [WARN] Upload returned HTTP %UPLOAD_CODE% - install manually
    goto SKIP_CONTENT_PACK
)
echo [OK] Content pack uploaded

REM Re-query by name to get reliable ID
timeout /t 1 /nobreak >nul 2>&1
curl -s -u "admin:%GRAYLOG_PASS%" -H "X-Requested-By: bootstrap" ^
    http://localhost:9000/api/system/content_packs > temp_packs.json 2>nul
for /f "tokens=*" %%i in ('python -c "import json; packs=json.load(open('temp_packs.json'))['content_packs']; print(next((p['id'] for p in packs if p.get('name')=='%CONTENT_PACK_NAME%'), ''))" 2^>nul') do set PACK_ID=%%i
del temp_packs.json 2>nul

if "%PACK_ID%"=="" (
    echo [WARN] Could not resolve content pack ID - install manually
    goto SKIP_CONTENT_PACK
)

:INSTALL_PACK
echo [..] Installing content pack ^(ID: %PACK_ID%^)...
curl -s -o nul -w "%%{http_code}" ^
    -u "admin:%GRAYLOG_PASS%" ^
    -H "X-Requested-By: bootstrap" ^
    -H "Content-Type: application/json" ^
    -X POST ^
    http://localhost:9000/api/system/content_packs/%PACK_ID%/1/installations ^
    -d "{\"parameters\":{},\"comment\":\"Installed by bootstrap\"}" > temp_install.txt 2>nul
set /p INSTALL_CODE=<temp_install.txt
del temp_install.txt 2>nul

if "%INSTALL_CODE%"=="200" (
    echo [OK] Content pack installed - streams, alerts, dashboards, inputs, notifications restored
) else if "%INSTALL_CODE%"=="201" (
    echo [OK] Content pack installed - streams, alerts, dashboards, inputs, notifications restored
) else (
    echo [WARN] Install returned HTTP %INSTALL_CODE% - verify in System -^> Content Packs
)

:SKIP_CONTENT_PACK

REM Give inputs a moment to start
timeout /t 3 /nobreak >nul 2>&1

REM Verify at least one input exists
curl -s -u "admin:%GRAYLOG_PASS%" http://localhost:9000/api/system/inputs > temp_inputs.json 2>nul
for /f "tokens=*" %%i in ('python -c "import json; print(json.load(open('temp_inputs.json')).get('total',0))" 2^>nul') do set INPUT_COUNT=%%i
del temp_inputs.json 2>nul
if "%INPUT_COUNT%"=="0" (
    echo [WARN] No Graylog inputs configured - logs will not be ingested.
) else (
    echo [OK] %INPUT_COUNT% Graylog input^(s^) configured
)

REM ─────────────────────────────────────────
REM Step 6 - Install Python deps + start generator
REM ─────────────────────────────────────────
echo.
echo [6/8] Installing Python dependencies and starting log generator...
echo.

python -m pip install requests --quiet >nul 2>&1
echo [OK] Python requests library installed

if not exist "logs" mkdir logs

REM Capture baseline via universal search (works across Graylog versions)
curl -s -u "admin:%GRAYLOG_PASS%" -H "Accept: application/json" ^
    "http://localhost:9000/api/search/universal/relative?query=*&range=300&limit=1" > temp_count.json 2>nul
for /f "tokens=*" %%i in ('python -c "import json; print(json.load(open('temp_count.json')).get('total_results',0))" 2^>nul') do set BASELINE=%%i
del temp_count.json 2>nul
if "%BASELINE%"=="" set BASELINE=0
echo [..] Baseline message count: %BASELINE%

echo [..] Starting log generator in background...
start /B python scripts\log_generator.py > logs\generator.log 2>&1
timeout /t 3 /nobreak >nul 2>&1
echo [OK] Log generator started

REM ─────────────────────────────────────────
REM Step 7 - Smoke test
REM ─────────────────────────────────────────
echo.
echo [7/8] Verifying end-to-end log flow...
echo.

set SMOKE_RETRIES=10
set SMOKE_COUNT=0
set LOGS_FLOWING=0

:SMOKE_LOOP
if %SMOKE_COUNT% geq %SMOKE_RETRIES% goto SMOKE_DONE
set /a SMOKE_COUNT+=1
timeout /t 3 /nobreak >nul 2>&1

curl -s -u "admin:%GRAYLOG_PASS%" -H "Accept: application/json" ^
    "http://localhost:9000/api/search/universal/relative?query=*&range=300&limit=1" > temp_count.json 2>nul
for /f "tokens=*" %%i in ('python -c "import json; print(json.load(open('temp_count.json')).get('total_results',0))" 2^>nul') do set CURRENT=%%i
del temp_count.json 2>nul
if "%CURRENT%"=="" set CURRENT=0

if %CURRENT% gtr %BASELINE% (
    set /a NEW_MSGS=%CURRENT%-%BASELINE%
    echo [OK] Logs flowing: !NEW_MSGS! new messages ingested ^(total: %CURRENT%^)
    set LOGS_FLOWING=1
    goto SMOKE_DONE
)

<nul set /p ".=."
goto SMOKE_LOOP

:SMOKE_DONE
echo.

if %LOGS_FLOWING% equ 0 (
    echo [WARN] No new messages detected after 30 seconds.
    echo        Possible causes:
    echo          - Content pack inputs not started - check System -^> Inputs in Graylog UI
    echo          - Log generator sending to wrong port - check logs\generator.log
    echo          - Firewall blocking localhost:1514 or localhost:12201
    echo.
    echo        Last 10 lines of generator log:
    echo        ---
    powershell -Command "Get-Content logs\generator.log -Tail 10" 2>nul
    echo        ---
)

REM ─────────────────────────────────────────
REM Step 8 - Start OmniLog AI assistant
REM ─────────────────────────────────────────
echo.
echo [8/8] Starting OmniLog AI assistant...
echo.

echo [..] Installing OmniLog Python dependencies...
python -m pip install -r ml\requirements.txt --quiet >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] OmniLog Python dependencies ready
) else (
    echo [WARN] Could not install OmniLog deps - run: pip install -r ml\requirements.txt
)

REM Kill any stale instances
taskkill /F /FI "WINDOWTITLE eq ml_service*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq omnilog_api*" >nul 2>&1
timeout /t 1 /nobreak >nul 2>&1

echo [..] Starting ML service (port 5001)...
start "ml_service" /B python scripts\ml_service.py > logs\ml_service.log 2>&1
timeout /t 3 /nobreak >nul 2>&1
echo [OK] ML service started

echo [..] Starting OmniLog API (port 5002)...
start "omnilog_api" /B python scripts\omnilog_api.py > logs\omnilog_api.log 2>&1
timeout /t 3 /nobreak >nul 2>&1
echo [OK] OmniLog API started

node --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if not exist "omnilog\node_modules" (
        echo [..] Installing OmniLog frontend dependencies (first run)...
        pushd omnilog
        call npm install --silent >nul 2>&1
        popd
    )
    echo [..] Starting OmniLog frontend (port 5173)...
    start "omnilog_ui" /B cmd /c "cd omnilog && node_modules\.bin\vite --port 5173 > ..\logs\omnilog_ui.log 2>&1"
    timeout /t 4 /nobreak >nul 2>&1
    echo [OK] OmniLog UI started - http://localhost:5173
) else (
    echo [WARN] Node.js not found - skipping OmniLog frontend. Install from https://nodejs.org
)

REM ─────────────────────────────────────────
REM Done
REM ─────────────────────────────────────────
echo.
echo =============================================================
if %LOGS_FLOWING% equ 1 (
    echo    Bootstrap complete - SIEM is fully operational!
) else (
    echo    Bootstrap complete - but verify logs manually.
)
echo =============================================================
echo.
echo   Graylog UI:    http://localhost:9000
echo   Username:      admin
echo   Password:      (from GRAYLOG_ADMIN_PASSWORD in .env)
echo   Attack Map:    http://localhost:8888
echo   OmniLog UI:    http://localhost:5173
echo   OmniLog API:   http://localhost:5002
echo   ML Service:    http://localhost:5001
echo.
echo   Log generator: running in background
echo   Generator log: logs\generator.log
echo.
echo   To generate a security report:
echo     python scripts\report_generator.py
echo.
echo   To stop everything:
echo     taskkill /F /IM python.exe
echo     taskkill /FI "WINDOWTITLE eq omnilog_ui*"
echo     docker compose down
echo.
echo =============================================================
echo.
pause
