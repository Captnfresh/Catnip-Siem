@echo off
REM =============================================================
REM Catnip Games SIEM - Bootstrap Script (Windows CMD)
REM Supports: Windows Command Prompt with Docker Desktop
REM Usage: Double-click bootstrap.bat
REM        OR in CMD: bootstrap.bat
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
echo [1/6] Checking dependencies...
echo.

docker --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker not found.
    echo         Please install Docker Desktop from https://docker.com
    echo         Then start Docker Desktop and wait for Engine Running.
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
echo [2/6] Checking Docker Desktop is running...
echo.

docker ps >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker Desktop is not running or not ready.
    echo         Please start Docker Desktop and wait for "Engine running"
    echo         at the bottom left before running this script.
    pause
    exit /b 1
)
echo [OK] Docker Desktop is running

REM ─────────────────────────────────────────
REM Step 3 - Check .env exists
REM ─────────────────────────────────────────
echo.
echo [3/6] Checking environment configuration...
echo.

if not exist ".env" (
    echo [ERROR] .env file not found.
    echo.
    echo   Please create your .env file first:
    echo     copy .env.example .env
    echo.
    echo   Then fill in the values shared with your team via WhatsApp.
    echo.
    pause
    exit /b 1
)
echo [OK] .env file found

REM Get password for API calls
if "%GRAYLOG_PASS%"=="" (
    echo.
    set /p GRAYLOG_PASS="Enter your Graylog admin password (for API calls): "
    echo.
)

REM ─────────────────────────────────────────
REM Step 4 - Start Docker stack
REM ─────────────────────────────────────────
echo.
echo [4/6] Starting Docker containers...
echo.

docker compose up -d
if %ERRORLEVEL% neq 0 (
    echo [ERROR] docker compose up failed.
    echo         Check your .env file and try again.
    pause
    exit /b 1
)

echo.
echo [..] Waiting for Graylog to become healthy...
echo      This takes 1-2 minutes. Please wait.
echo.

set RETRIES=60
set COUNT=0
set HEALTHY=0

:WAIT_LOOP
if %COUNT% geq %RETRIES% goto TIMEOUT
set /a COUNT+=1
<nul set /p ".=."
timeout /t 3 /nobreak >nul 2>&1

curl -s -u "admin:%GRAYLOG_PASS%" -H "Accept: application/json" ^
    http://localhost:9000/api/system/lbstatus 2>nul | find "ALIVE" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set HEALTHY=1
    goto HEALTHY_CHECK
)
goto WAIT_LOOP

:TIMEOUT
echo.
echo [ERROR] Graylog did not become healthy in time.
echo         Run: docker compose logs graylog
pause
exit /b 1

:HEALTHY_CHECK
echo.
echo [OK] Graylog is healthy

REM ─────────────────────────────────────────
REM Step 5 - Install content pack
REM ─────────────────────────────────────────
echo.
echo [5/6] Installing Graylog content pack...
echo.

set CONTENT_PACK=content-packs\catnip-siem-pack.json

if not exist "%CONTENT_PACK%" (
    echo [SKIP] Content pack not found at: %CONTENT_PACK%
    echo        Install manually: System -^> Content Packs -^> Upload
    goto SKIP_CONTENT_PACK
)

echo [..] Uploading content pack...

for /f "tokens=*" %%r in ('curl -s -w "%%{http_code}" ^
    -u "admin:%GRAYLOG_PASS%" ^
    -H "X-Requested-By: bootstrap" ^
    -H "Content-Type: application/json" ^
    -X POST ^
    http://localhost:9000/api/system/content_packs ^
    -d @"%CONTENT_PACK%" 2^>nul') do set UPLOAD_RESULT=%%r

echo %UPLOAD_RESULT% | find "400" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [SKIP] Content pack already exists in Graylog
    goto SKIP_CONTENT_PACK
)

echo [OK] Content pack uploaded
echo [..] Installing content pack...
echo      Note: Copy the content pack ID from Graylog UI if needed
echo      System -^> Content Packs -^> find Catnip Games SIEM -^> Install

:SKIP_CONTENT_PACK

REM ─────────────────────────────────────────
REM Step 6 - Install Python deps + start generator
REM ─────────────────────────────────────────
echo.
echo [6/6] Installing Python dependencies and starting log generator...
echo.

python -m pip install requests --quiet >nul 2>&1
echo [OK] Python requests library installed

if not exist "logs" mkdir logs

echo [..] Starting log generator in background...
start /B python scripts\log_generator.py > logs\generator.log 2>&1
timeout /t 2 /nobreak >nul 2>&1
echo [OK] Log generator started

REM ─────────────────────────────────────────
REM Done
REM ─────────────────────────────────────────
echo.
echo =============================================================
echo    Bootstrap complete!
echo =============================================================
echo.
echo   Graylog UI:   http://localhost:9000
echo   Username:     admin
echo   Password:     (from your .env file)
echo.
echo   Log generator is running in the background
echo   Generator log: logs\generator.log
echo.
echo   To generate a security report:
echo     set GRAYLOG_PASS=your_password
echo     python scripts\report_generator.py
echo.
echo   To stop all containers:
echo     docker compose down
echo.
echo =============================================================
echo.
pause
