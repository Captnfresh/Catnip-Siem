# Catnip Games International — Security Monitoring SIEM

[![Graylog](https://img.shields.io/badge/Graylog-6.1-orange)](https://graylog.org)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.15.0-blue)](https://opensearch.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-7-green)](https://mongodb.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](https://docker.com)
[![Python](https://img.shields.io/badge/Python-3.x-yellow)](https://python.org)
[![ML](https://img.shields.io/badge/ML-scikit--learn-orange)](https://scikit-learn.org)
[![AI](https://img.shields.io/badge/AI-Claude%20API-blueviolet)](https://anthropic.com)
[![React](https://img.shields.io/badge/React-18-61DAFB)](https://react.dev)

---

## What This Project Is

A fully operational AI-powered SIEM (Security Information and Event Management) system built for the **Cyber Security Automation** module at the University of Roehampton.

The system monitors a fictional gaming company (Catnip Games International) and includes:

- **Graylog** — real-time log ingestion, stream routing, dashboards, and rule-based alerting
- **OmniLog** — AI-powered security analyst interface (React frontend + Flask API) powered by Claude
- **ML Engine** — machine learning threat severity scoring and zero-day anomaly detection
- **Live Attack Map** — real-time geographic visualisation of attack sources
- **Log Generator** — simulates 300 game servers, player authentication, DDoS, and SSH attacks

---

## Prerequisites

Install all of these before you begin. The bootstrap will check for them and tell you if anything is missing.

| Tool | Minimum Version | Download |
|---|---|---|
| Docker Desktop | Latest | [docker.com](https://docker.com) |
| Git | Any | [git-scm.com](https://git-scm.com) |
| Python | 3.9+ | [python.org](https://python.org) |
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |

> **Windows users:** Make sure Docker Desktop is fully started (taskbar icon shows "Engine running") before running the bootstrap. If you see "Starting the Docker Engine..." indefinitely, open Task Manager, end any `com.docker.backend.exe` processes, and restart Docker Desktop.

> **Linux / WSL users:** The bootstrap sets the OpenSearch kernel parameter automatically, but you must run it with a user that has `sudo` access.

---

## Getting Started — Clone and Run

### Step 1 — Clone the repository

```bash
git clone https://github.com/D-rank-developer/Catnip-Siem.git
cd Catnip-Siem
```

### Step 2 — Create your environment file

```bash
# Mac / Linux / WSL
cp .env.example .env

# Windows CMD
copy .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

Open `.env` in any text editor and fill in the values:

```env
# ── Graylog ──────────────────────────────────────────────────────
# Random 64+ character string. Generate with: pwgen -N 1 -s 96
GRAYLOG_PASSWORD_SECRET=change_me_to_a_random_64_char_string

# SHA256 of your chosen admin password.
# Mac/Linux: echo -n "YourPassword" | sha256sum
# Windows:   (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes("YourPassword"))) -Algorithm SHA256).Hash.ToLower()
GRAYLOG_ROOT_PASSWORD_SHA2=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918

# The SAME password in plaintext — needed by the bootstrap to call the Graylog API
GRAYLOG_ADMIN_PASSWORD=admin

# Leave as-is for local development
GRAYLOG_HTTP_EXTERNAL_URI=http://localhost:9000/

# ── OpenSearch ───────────────────────────────────────────────────
OPENSEARCH_ADMIN_PASSWORD=YourStrongPassword123!

# ── Email alerts (optional — leave blank to disable) ─────────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=

# ── OmniLog AI (Claude) ──────────────────────────────────────────
# Get your key at https://console.anthropic.com
# Without this, OmniLog uses keyword-based analysis as a fallback
ANTHROPIC_API_KEY=
```

> **Important:** `GRAYLOG_ADMIN_PASSWORD` must be the exact plaintext whose SHA256 hash you put in `GRAYLOG_ROOT_PASSWORD_SHA2`. The example values above (`admin` / its SHA256 hash) work together — change both to something stronger in production.

### Step 3 — Run the bootstrap

The bootstrap script does everything: starts Docker, waits for Graylog, installs the content pack (restoring all streams, dashboards, alert rules, extractors), installs Python dependencies, starts the ML service, OmniLog API, log generator, frontend, and runs a smoke test.

**Mac / Linux / WSL:**
```bash
chmod +x bootstrap.sh
./bootstrap.sh
```

**Windows PowerShell** (run as normal user, not administrator):
```powershell
.\bootstrap.ps1
```

**Windows CMD:**
```
bootstrap.bat
```

The script takes 2–4 minutes on first run (mostly waiting for Graylog and OpenSearch to initialise). You will see step-by-step progress:

```
=============================================================
   Catnip Games International - SIEM Bootstrap (PowerShell)
=============================================================

[1/8] Checking dependencies...
[OK] Docker found
[OK] Python found: Python 3.12.x

[2/8] Checking Docker Desktop is running...
[OK] Docker Desktop is running

[3/8] Checking environment configuration...
[OK] .env file found
[OK] Graylog admin credentials loaded from .env

[4/8] Starting Docker containers...
[OK] Graylog is ready
[OK] Graylog authentication verified

[5/8] Installing Graylog content pack...
[OK] Content pack installed — streams, alerts, dashboards, inputs, notifications restored
[OK] 3 Graylog input(s) configured

[6/8] Installing Python dependencies and starting background services...
[OK] Python dependencies installed
[OK] Log generator running (PID: XXXXX)
[OK] Live attack map running — http://localhost:8888

[7/8] Verifying end-to-end log flow...
[OK] Logs flowing: 47 new messages ingested (total: 47)

[8/8] Starting OmniLog AI assistant...
[OK] ML model found
[OK] ML service running (PID: XXXXX)
[OK] OmniLog API running (PID: XXXXX)
[OK] OmniLog UI running (PID: XXXXX) — http://localhost:5173

=============================================================
   Bootstrap complete — SIEM is fully operational!
=============================================================

  Graylog UI:    http://localhost:9000
  Username:      admin
  Password:      (from GRAYLOG_ADMIN_PASSWORD in .env)
  Attack Map:    http://localhost:8888
  OmniLog UI:    http://localhost:5173
  OmniLog API:   http://localhost:5002
  ML Service:    http://localhost:5001
```

### Step 4 — Open the interfaces

| URL | What it is |
|---|---|
| http://localhost:9000 | Graylog — dashboards, streams, alert rules, raw log search |
| http://localhost:5173 | OmniLog — AI analyst, zero-day alerts, threat reports |
| http://localhost:8888 | Live attack map — geographic threat visualisation |
| http://localhost:5002/status | OmniLog API health check (JSON) |

Log into Graylog with username `admin` and the password from `GRAYLOG_ADMIN_PASSWORD` in your `.env`.

---

## After a Restart

When you close your laptop, shut down, or restart WSL, Docker containers stop and the Python processes die. Run the bootstrap again — it is safe to run repeatedly and skips any steps that are already done (content pack, npm install, etc.).

```bash
./bootstrap.sh        # Mac / Linux / WSL
.\bootstrap.ps1       # Windows PowerShell
```

Or restart manually if you prefer:

**Mac / Linux / WSL:**
```bash
# 1. Start Docker containers
docker compose up -d

# 2. Install Python deps (first time only — skip on subsequent runs)
pip install -r ml/requirements.txt

# 3. Start ML service on port 5001
nohup python scripts/ml_service.py > logs/ml_service.log 2>&1 &
echo "ML service PID: $!"

# 4. Start OmniLog API on port 5002
nohup python scripts/omnilog_api.py > logs/omnilog_api.log 2>&1 &
echo "OmniLog API PID: $!"

# 5. Start log generator (sends GELF to Graylog TCP 12201)
nohup python scripts/log_generator.py > logs/generator.log 2>&1 &
echo "Log generator PID: $!"

# 6. Start live attack map on port 8888
nohup python geomap/geomap.py > logs/geomap.log 2>&1 &
echo "Geomap PID: $!"

# 7. Start OmniLog frontend on port 5173 (run in a separate terminal)
cd omnilog && npm run dev
```

**Windows PowerShell:**
```powershell
# Run all of these from the Catnip-Siem project directory
$dir  = (Get-Location).Path
$logs = "$dir\logs"
if (-not (Test-Path $logs)) { New-Item -ItemType Directory -Path $logs | Out-Null }

# 1. Start Docker containers
docker compose up -d

# 2. Install Python deps (first time only)
python -m pip install -r ml\requirements.txt --quiet

# 3. Start ML service on port 5001
$ml = Start-Process python -ArgumentList "-u", "scripts\ml_service.py" `
    -WorkingDirectory $dir `
    -RedirectStandardOutput "$logs\ml_service.log" `
    -RedirectStandardError  "$logs\ml_service_error.log" `
    -WindowStyle Hidden -PassThru
Write-Host "ML service PID: $($ml.Id)"

# 4. Start OmniLog API on port 5002
$api = Start-Process python -ArgumentList "-u", "scripts\omnilog_api.py" `
    -WorkingDirectory $dir `
    -RedirectStandardOutput "$logs\omnilog_api.log" `
    -RedirectStandardError  "$logs\omnilog_api_error.log" `
    -WindowStyle Hidden -PassThru
Write-Host "OmniLog API PID: $($api.Id)"

# 5. Start log generator (sends GELF to Graylog TCP 12201)
$gen = Start-Process python -ArgumentList "-u", "scripts\log_generator.py" `
    -WorkingDirectory $dir `
    -RedirectStandardOutput "$logs\generator.log" `
    -RedirectStandardError  "$logs\generator_error.log" `
    -WindowStyle Hidden -PassThru
Write-Host "Log generator PID: $($gen.Id)"

# 6. Start live attack map on port 8888
$geo = Start-Process python -ArgumentList "-u", "geomap\geomap.py" `
    -WorkingDirectory $dir `
    -RedirectStandardOutput "$logs\geomap.log" `
    -RedirectStandardError  "$logs\geomap_error.log" `
    -WindowStyle Hidden -PassThru
Write-Host "Geomap PID: $($geo.Id)"

# 7. Start OmniLog frontend on port 5173 (open a new terminal for this)
# cd omnilog; npm run dev
$vite = Start-Process "$dir\omnilog\node_modules\.bin\vite.cmd" `
    -ArgumentList "--port", "5173" `
    -WorkingDirectory "$dir\omnilog" `
    -RedirectStandardOutput "$logs\omnilog_ui.log" `
    -WindowStyle Hidden -PassThru
Write-Host "OmniLog UI PID: $($vite.Id)"
```

**Verify all services are responding:**
```powershell
# Health-check all services (run after ~5 seconds)
@(
  @{ Name="ML Service";  Url="http://localhost:5001/health" },
  @{ Name="OmniLog API"; Url="http://localhost:5002/health" },
  @{ Name="Geomap";      Url="http://localhost:8888" },
  @{ Name="OmniLog UI";  Url="http://localhost:5173" }
) | ForEach-Object {
  try {
    $r = Invoke-WebRequest -Uri $_.Url -UseBasicParsing -TimeoutSec 5
    Write-Host "[OK]   $($_.Name)"
  } catch {
    Write-Host "[FAIL] $($_.Name)"
  }
}
```

**View service logs in real time:**
```powershell
# Log generator output (should show events every ~1 second)
Get-Content logs\generator.log -Wait -Tail 20

# OmniLog API log
Get-Content logs\omnilog_api.log -Wait -Tail 20

# ML service log
Get-Content logs\ml_service.log -Wait -Tail 20
```

---

## Stopping Everything

```bash
# Stop the Python services
pkill -f log_generator.py       # Mac/Linux/WSL
pkill -f geomap.py
pkill -f ml_service.py
pkill -f omnilog_api.py
pkill -f vite

# Windows PowerShell equivalent
Stop-Process -Name python -Force

# Stop the Vite dev server (if running in its own terminal, just Ctrl+C)

# Stop Docker containers
docker compose down
```

To also delete all stored log data and start completely fresh:
```bash
docker compose down -v    # WARNING: deletes all Graylog data
```

---

## OmniLog AI Assistant

OmniLog is the React-based security analyst interface. It connects to Claude (Anthropic API) to answer natural-language questions about your logs.

### Asking questions

Type any security question in plain English:

- `"Show me all failed logins in the last hour"`
- `"Is there a brute force attack happening right now?"`
- `"What are the top attacking IP addresses?"`
- `"Explain what's happening with the game servers"`
- `"Are there any signs of credential stuffing?"`

Claude will query Graylog, score events through the ML engine, and reply in plain English with findings, severity, and recommended actions.

### Sidebar quick filters

Click any category in the left sidebar to expand a live event dropdown:

| Filter | What it shows |
|---|---|
| Failed Logins | Authentication failures, brute force attempts |
| Errors | Critical/error-level system events |
| Network Activity | Firewall, DNS, and network traffic anomalies |
| Suspicious Behaviour | Unusual login patterns, lateral movement indicators |
| Zero-Day Alerts | ML-detected threats with no matching Graylog rule |

Each event card is clickable — clicking it sends that event to Claude for immediate investigation.

### Zero-Day Alerts

The Zero-Day panel runs IsolationForest (unsupervised ML) over the last 200 events. It surfaces two types of threats Graylog's rule-based system cannot catch:

1. **Zero-day anomalies** — events that deviate significantly from learned baseline behaviour
2. **High-confidence ML detections** — events the ML classifier rates as high/critical severity even though no Graylog alert rule fired

Each threat card shows:
- **ML assessment** — what the ML model detected, with confidence percentage
- **Graylog assessment** — what Graylog's rule-based system saw for the same event
- **Delta** — a plain-English explanation of the difference (e.g. "Graylog classified as 'Normal Traffic [info]' but ML identified 'SSH Brute Force' with 87% confidence. Severity escalated by ML: info → high.")

### Print Report

Click **Print Report** in the top-right corner to generate a full security report:

1. Select a time range (Last 1 hour / 6 hours / 24 hours / 7 days, or custom From/To timestamps)
2. Click **Generate & Print Report**
3. OmniLog fetches up to 10,000 logs from Graylog, runs ML scoring on 200 representative events, maps detected threats to CVEs, and generates a remediation plan
4. A print-ready report opens in a new window with an executive summary, threat breakdown, CVE mappings, and step-by-step remediation

---

## ML Engine

The ML engine runs as a separate Flask service on port 5001. It provides two models:

| Model | Type | Purpose |
|---|---|---|
| Severity classifier | Gradient Boosting | Rates each log event as info/low/medium/high/critical/emergency |
| Zero-day detector | IsolationForest | Detects anomalous events with no known attack signature |

The IsolationForest auto-trains on the first 200+ live Graylog events when you open the Zero-Day Alerts panel. No pre-training required.

The pre-trained severity model (`models/catnip_severity_model.pkl`) ships with the repository. If it is missing, the ML service still starts but zero-day detection will be the only available function.

---

## Architecture

![Catnip Games SIEM Architecture](assets/architecture-diagram.svg)

> **Important — GELF TCP not UDP:** Docker Desktop on Windows silently drops UDP port forwarding for port 12201. The log generator uses GELF over TCP (null-byte delimited) which Docker Desktop forwards reliably. The Graylog content pack includes a GELF TCP input on port 12201. Do not change this to UDP — messages will be silently lost.

---

## Repository Structure

```
Catnip-Siem/
├── docker-compose.yml              # Full stack definition
├── .env.example                    # Environment variable template
├── bootstrap.sh                    # One-command setup — Mac, Linux, WSL
├── bootstrap.ps1                   # One-command setup — Windows PowerShell
├── bootstrap.bat                   # One-command setup — Windows CMD
│
├── scripts/
│   ├── log_generator.py            # Simulates Catnip Games infrastructure
│   │                               # (GELF TCP → Graylog port 12201)
│   ├── omnilog_api.py              # Flask API — Claude + Graylog + ML bridge
│   ├── ml_service.py               # Flask ML service (port 5001)
│   └── report_generator.py        # CLI security report
│
├── ml/
│   ├── model.py                    # GradientBoosting severity classifier
│   ├── zero_day.py                 # IsolationForest zero-day detector
│   └── requirements.txt            # Python dependencies for all services
│
├── models/
│   └── catnip_severity_model.pkl   # Pre-trained severity model
│
├── omnilog/                        # React frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── AppSidebar.tsx      # Sidebar with live event dropdowns
│   │   │   ├── TopBar.tsx          # Print Report button + time range picker
│   │   │   ├── PrintReport.tsx     # Report modal + print window generator
│   │   │   └── RiskGauge.tsx       # Animated risk score gauge
│   │   └── lib/api.ts              # API client (typed fetch wrappers)
│   ├── public/favicon.svg          # OmniLog shield/eye icon
│   └── index.html                  # App entry point
│
├── content-packs/
│   └── catnip-siem-pack.json       # Full Graylog config snapshot
│                                   # (streams, alerts, dashboards, inputs,
│                                   #  extractors, notifications)
├── geomap/
│   └── geomap.py                   # Live attack map (Flask, port 8888)
│
└── docs/
    ├── platform-setup.md
    ├── log-ingestion.md
    ├── alert-rules.md
    └── dashboards.md
```

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `GRAYLOG_PASSWORD_SECRET` | Yes | Random 64+ char string for Graylog encryption |
| `GRAYLOG_ROOT_PASSWORD_SHA2` | Yes | SHA256 hash of the admin password |
| `GRAYLOG_ADMIN_PASSWORD` | Yes | Plaintext admin password (must match hash above) |
| `GRAYLOG_HTTP_EXTERNAL_URI` | Yes | `http://localhost:9000/` for local dev |
| `OPENSEARCH_ADMIN_PASSWORD` | Yes | Min 8 chars, 1 uppercase, 1 number, 1 special char |
| `SMTP_HOST` | No | Email server for alert notifications |
| `SMTP_PORT` | No | Usually 587 for TLS |
| `SMTP_USER` | No | Email address for sending alerts |
| `SMTP_PASSWORD` | No | Email password or app-specific password |
| `ANTHROPIC_API_KEY` | No | Enables Claude AI in OmniLog (falls back to keyword matching without it) |
| `GRAYLOG_HOST` | No | Defaults to `localhost` |
| `GRAYLOG_PORT` | No | Defaults to `9000` |
| `ML_SERVICE_URL` | No | Defaults to `http://localhost:5001` |
| `OMNILOG_PORT` | No | Defaults to `5002` |

---

## Graylog Content Pack

The content pack (`content-packs/catnip-siem-pack.json`) is a complete snapshot of the Graylog configuration. The bootstrap installs it automatically. It restores:

- **3 inputs** — GELF TCP (port 12201), Syslog TCP (port 1514), Syslog UDP (port 1514)
- **5 streams** — Game Servers, Player Auth, SSH Auth, Dev Environment, All Events
- **4 alert rules** — SSH Brute Force, DDoS, Credential Stuffing, Suspicious Dev Login
- **5 dashboards** — Security Overview, SSH Auth Monitoring, Game Server Health, Player Auth, Dev Environment
- **Extractors** — parse `action`, `event_type`, `severity`, `source_ip`, `target_user` from raw messages
- **Notifications** — email alerts via configured SMTP

If the content pack install fails, you can install it manually: **Graylog UI → System → Content Packs → Upload** → select `content-packs/catnip-siem-pack.json` → Install.

---

## Troubleshooting

### OmniLog shows "DISCONNECTED" or active alerts is 0

Check that all services are running:

```bash
# Check Docker containers
docker compose ps

# Check Python services
ps aux | grep -E "ml_service|omnilog_api|log_generator"    # Mac/Linux
wmic process where "name like '%python%'" get CommandLine   # Windows

# Check OmniLog API status
curl http://localhost:5002/status
```

Expected output from the status check:
```json
{
  "graylog_connected": true,
  "ml_service_connected": true,
  "active_alerts": 12,
  "risk_score": 48,
  "total_events_last_hour": 150
}
```

If `total_events_last_hour` is 0 or very low, the log generator is not reaching Graylog. Restart it:

```bash
# Mac/Linux/WSL
pkill -f log_generator.py
python scripts/log_generator.py > logs/generator.log 2>&1 &

# Windows PowerShell
Stop-Process -Name python -Force
Start-Process python -ArgumentList "scripts/log_generator.py"
```

### "graylog_connected: false"

1. Make sure the Docker containers are running: `docker compose ps`
2. Try opening http://localhost:9000 in a browser — if it loads, Graylog is up
3. Check your `.env` has `GRAYLOG_ADMIN_PASSWORD` set to the correct plaintext password
4. Restart the OmniLog API: kill its process and run `python scripts/omnilog_api.py` again

### Graylog receives 0 logs (total_events_last_hour stays 0)

This is almost always a GELF TCP delivery issue. Verify:

```bash
# Check that TCP 12201 is listening
netstat -an | grep 12201

# You should see a TCP LISTENING line, e.g.:
# TCP    0.0.0.0:12201    0.0.0.0:0    LISTENING
```

If you only see `UDP 0.0.0.0:12201` but no TCP line, run `docker compose up -d` to recreate the container (which now maps TCP 12201) and then create the GELF TCP input in Graylog: **System → Inputs → Launch new input → GELF TCP → port 12201 → Global → Save**.

### OpenSearch container keeps restarting

```bash
# Linux/WSL only — set the required kernel parameter
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
docker compose up -d
```

On Mac and Windows, Docker Desktop manages this automatically.

### OmniLog UI shows blank screen or won't load

```bash
# Make sure npm dependencies are installed
cd omnilog
npm install
npm run dev
```

If you see TypeScript errors, try clearing the Vite cache:
```bash
cd omnilog
rm -rf node_modules/.vite
npm run dev
```

### Graylog shows duplicate streams or inputs after reinstall

This happens when `docker compose down -v` is run from one Docker context (e.g. WSL) while Docker Desktop was managing the containers. Run:

```bash
docker rm -f catnip-graylog catnip-mongodb catnip-opensearch
docker volume rm catnip-siem_graylog_data catnip-siem_mongodb_data catnip-siem_opensearch_data
docker compose up -d
./bootstrap.sh
```

### OmniLog falls back to mock data / no Claude responses

Set `ANTHROPIC_API_KEY` in your `.env` file. Get a key at https://console.anthropic.com. Without it, the chat interface still works but uses keyword-based analysis instead of Claude.

---

## Dashboards

Five dashboards answer specific security questions:

| Dashboard | What it shows |
|---|---|
| Security Overview | Overall threat picture — event totals, timeline, type breakdown |
| SSH Auth Monitoring | Brute force attacks — failed logins over time, attacking IPs, targeted usernames |
| Game Server Health | DDoS attacks — traffic anomalies, targeted servers, attack timeline |
| Player Auth Monitoring | Credential stuffing — login outcomes, targeted players |
| Dev Environment Security | Dev server access — suspicious logins, targeted accounts |

---

## Alert Rules

Four automated alerts fire email notifications when thresholds are crossed:

| Alert | Trigger condition |
|---|---|
| SSH Brute Force | 10+ failed SSH logins from one IP within 5 minutes |
| DDoS Attack | Any DDoS event detected (immediate, no threshold) |
| Credential Stuffing | 20+ stuffing attempts from one IP within 5 minutes |
| Suspicious Dev Login | Any suspicious login to a developer server |

---

## Known Limitations

**GELF UDP silently dropped on Windows:** Docker Desktop on Windows does not reliably forward UDP ports from the host to containers. This project uses GELF over TCP (port 12201) instead. Do not change the log generator back to UDP — all messages will be silently discarded.

**Simulated infrastructure:** The log generator replaces real game server infrastructure. In production, rsyslog agents on each server would replace the generator.

**Single-node deployment:** No high availability. A production deployment would require a multi-node OpenSearch cluster and Graylog cluster.

**ML model is pre-trained:** The severity model was trained on synthetic Catnip Games log data. It will still work on real infrastructure but may need retraining on live data for optimal accuracy.

**Claude API key optional:** Without `ANTHROPIC_API_KEY`, OmniLog's chat uses simple keyword-to-query translation. The zero-day alerts, dashboard counts, and print report all work without it.

---

## Project Team

| Name | Contribution |
|---|---|
| Adebowale (Team Lead) | Docker infrastructure, log generator, report script, bootstrap scripts, architecture |
| Stephen | Graylog platform deployment and maintenance |
| Lekan | Inputs, extractors, rsyslog configuration, streams |
| Faith | Alert event definitions, notifications, remediation procedures |
| Akhamas | 5 dashboards, 20 widgets, visualisation design |
| Chamberlain | OmniLog AI frontend + API, ML service integration, zero-day detection, CVE mapping, print report, branding, debugging |

---

## Module Context

Built for the **Cyber Security Automation** module at the University of Roehampton.

- **Work Role:** DCWF 511 — Cyber Defense Analyst
- **Competency:** Uses data collected from cyber defense tools to analyse events for the purposes of mitigating threats
- **Assessment:** In-lab team demonstration with individual Q&A
