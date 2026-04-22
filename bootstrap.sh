#!/bin/bash
# =============================================================
# Catnip Games SIEM - Bootstrap Script
# Supports: Mac, Linux, WSL (Windows Subsystem for Linux), Kali
# Usage: ./bootstrap.sh
# =============================================================

set -e

# ─────────────────────────────────────────
# Colours
# ─────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
info() { echo -e "${YELLOW}[..] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }
step() { echo -e "\n${CYAN}$1${NC}"; }

# Robust .env variable reader — handles CRLF, quotes, and whitespace
read_env_var() {
    local var_name="$1"
    local env_file="${2:-.env}"
    grep "^${var_name}=" "$env_file" 2>/dev/null | \
        head -1 | \
        cut -d'=' -f2- | \
        tr -d '\r' | \
        sed 's/^["'\'']//;s/["'\'']$//'
}

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
GRAYLOG_URL="http://localhost:9000"
GRAYLOG_USER="admin"
CONTENT_PACK_FILE="$(dirname "$0")/content-packs/catnip-siem-pack.json"
CONTENT_PACK_NAME="Catnip Games SIEM"
SCRIPTS_DIR="$(dirname "$0")/scripts"
LOGS_DIR="$(dirname "$0")/logs"
GENERATOR_LOG="$LOGS_DIR/generator.log"

# ─────────────────────────────────────────
# Header
# ─────────────────────────────────────────
echo ""
echo "============================================================="
echo "   Catnip Games International — SIEM Bootstrap"
echo "============================================================="
echo ""

# ─────────────────────────────────────────
# Step 1 — Detect OS
# ─────────────────────────────────────────
step "[1/8] Detecting operating system..."

OS="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
    ok "macOS detected"
elif grep -qi microsoft /proc/version 2>/dev/null; then
    OS="wsl"
    ok "WSL (Windows Subsystem for Linux) detected"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    ok "Linux detected"
else
    fail "Unsupported operating system: $OSTYPE"
fi

# ─────────────────────────────────────────
# Step 2 — Check dependencies
# ─────────────────────────────────────────
step "[2/8] Checking dependencies..."

if ! command -v docker &>/dev/null; then
    fail "Docker not found. Please install Docker Desktop from https://docker.com and try again."
fi
ok "Docker found: $(docker --version)"

if ! docker compose version &>/dev/null; then
    fail "Docker Compose not found. Please update Docker Desktop and try again."
fi
ok "Docker Compose found"

if ! command -v python3 &>/dev/null; then
    fail "Python3 not found. Please install Python 3 from https://python.org and try again."
fi
ok "Python3 found: $(python3 --version)"

if ! command -v curl &>/dev/null; then
    fail "curl not found. Please install curl and try again."
fi

# ─────────────────────────────────────────
# Step 3 — Set vm.max_map_count (Linux/WSL only)
# ─────────────────────────────────────────
step "[3/8] Configuring system settings..."

if [[ "$OS" == "wsl" || "$OS" == "linux" ]]; then
    info "Setting vm.max_map_count=262144 (required by OpenSearch)..."
    sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || \
        warn "Could not set vm.max_map_count — may need to run with sudo"
    if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf 2>/dev/null; then
        echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf >/dev/null 2>&1 || true
        ok "vm.max_map_count configured"
    else
        ok "vm.max_map_count already configured"
    fi
else
    ok "macOS — vm.max_map_count not required (Docker Desktop manages this)"
fi

# ─────────────────────────────────────────
# Step 4 — Check .env, auto-fix CRLF, load password
# ─────────────────────────────────────────
step "[4/8] Checking environment configuration..."

if [ ! -f ".env" ]; then
    echo ""
    echo -e "${RED}[ERROR] .env file not found.${NC}"
    echo ""
    echo "  Please create your .env file first:"
    echo ""
    echo "    cp .env.example .env"
    echo ""
    echo "  Then fill in the values shared with your team via WhatsApp."
    echo "  Required variables:"
    echo "    GRAYLOG_PASSWORD_SECRET"
    echo "    GRAYLOG_ROOT_PASSWORD_SHA2"
    echo "    GRAYLOG_ADMIN_PASSWORD   (plaintext, for API calls)"
    echo "    GRAYLOG_HTTP_EXTERNAL_URI"
    echo "    OPENSEARCH_ADMIN_PASSWORD"
    echo "    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD"
    echo ""
    exit 1
fi
ok ".env file found"

# Auto-fix Windows CRLF line endings (silent — happens every run, harmless on Unix files)
if grep -q $'\r' .env 2>/dev/null; then
    sed -i 's/\r$//' .env
    info "Normalised line endings in .env (Windows CRLF → Unix LF)"
fi

# Load plaintext admin password from .env (NOT the SHA2 hash)
if [ -z "$GRAYLOG_PASS" ]; then
    GRAYLOG_PASS=$(read_env_var "GRAYLOG_ADMIN_PASSWORD")
fi

if [ -z "$GRAYLOG_PASS" ]; then
    echo ""
    echo -e "${RED}[ERROR] GRAYLOG_ADMIN_PASSWORD not set in .env${NC}"
    echo ""
    echo "  Add this line to your .env file:"
    echo "    GRAYLOG_ADMIN_PASSWORD=<the plaintext admin password>"
    echo ""
    echo "  This is the plaintext password whose SHA256 hash is stored in"
    echo "  GRAYLOG_ROOT_PASSWORD_SHA2. The bootstrap needs it to authenticate"
    echo "  to the Graylog API."
    echo ""
    exit 1
fi
ok "Graylog admin credentials loaded from .env"

# ─────────────────────────────────────────
# Step 5 — Start Docker stack and wait for Graylog
# ─────────────────────────────────────────
step "[5/8] Starting Docker containers..."

info "Running docker compose up -d..."
docker compose up -d

echo ""
info "Waiting for Graylog to become ready (this takes 1-2 minutes)..."

RETRIES=60
COUNT=0
READY=0

while [ $COUNT -lt $RETRIES ]; do
    RESPONSE=$(curl -s -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
        "$GRAYLOG_URL/api/system/lbstatus" 2>/dev/null || echo "")

    if echo "$RESPONSE" | grep -q "ALIVE"; then
        READY=1
        break
    fi

    COUNT=$((COUNT + 1))
    printf "."
    sleep 3
done

echo ""

if [ $READY -ne 1 ]; then
    fail "Graylog did not become ready after $((RETRIES * 3)) seconds. Run: docker compose logs graylog"
fi

ok "Graylog is ready"

# Verify credentials work against an authenticated endpoint
AUTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
    "$GRAYLOG_URL/api/users" 2>/dev/null)

if [ "$AUTH_CHECK" != "200" ]; then
    fail "Graylog authentication failed (HTTP $AUTH_CHECK). Check GRAYLOG_ADMIN_PASSWORD in .env matches the password used to generate GRAYLOG_ROOT_PASSWORD_SHA2."
fi
ok "Graylog authentication verified"

# ─────────────────────────────────────────
# Step 6 — Install content pack (idempotent, robust)
# ─────────────────────────────────────────
step "[6/8] Installing Graylog content pack..."

# Helper: find content pack ID by name (returns empty string if not found)
find_pack_id_by_name() {
    curl -s -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
        -H "X-Requested-By: bootstrap" \
        "$GRAYLOG_URL/api/system/content_packs" 2>/dev/null | \
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for p in data.get('content_packs', []):
        if p.get('name') == '$CONTENT_PACK_NAME':
            print(p.get('id', ''))
            break
except Exception:
    pass
" 2>/dev/null
}

if [ ! -f "$CONTENT_PACK_FILE" ]; then
    warn "Content pack not found at: $CONTENT_PACK_FILE"
    echo "       Install manually: System → Content Packs → Upload"
else
    # Step 6a: Upload (skip if already uploaded)
    info "Checking for existing content pack..."
    PACK_ID=$(find_pack_id_by_name)

    if [ -n "$PACK_ID" ]; then
        ok "Content pack already uploaded (ID: $PACK_ID)"
    else
        info "Uploading content pack..."
        UPLOAD_CODE=$(curl -s -o /tmp/catnip_upload_response.json -w "%{http_code}" \
            -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
            -H "X-Requested-By: bootstrap" \
            -H "Content-Type: application/json" \
            -X POST \
            "$GRAYLOG_URL/api/system/content_packs" \
            -d @"$CONTENT_PACK_FILE" 2>/dev/null)

        if [[ "$UPLOAD_CODE" == "201" || "$UPLOAD_CODE" == "200" ]]; then
            ok "Content pack uploaded"
            # Re-query by name to get the ID reliably (don't rely on upload response parsing)
            sleep 1
            PACK_ID=$(find_pack_id_by_name)
        else
            warn "Upload returned HTTP $UPLOAD_CODE"
            echo "       Response: $(cat /tmp/catnip_upload_response.json 2>/dev/null | head -c 200)"
            PACK_ID=""
        fi
        rm -f /tmp/catnip_upload_response.json
    fi

    # Step 6b: Install (always attempt — Graylog is idempotent on re-install)
    if [ -n "$PACK_ID" ]; then
        info "Installing content pack (ID: $PACK_ID)..."
        INSTALL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
            -H "X-Requested-By: bootstrap" \
            -H "Content-Type: application/json" \
            -X POST \
            "$GRAYLOG_URL/api/system/content_packs/$PACK_ID/1/installations" \
            -d '{"parameters":{},"comment":"Installed by bootstrap"}' 2>/dev/null)

        if [[ "$INSTALL_CODE" == "200" || "$INSTALL_CODE" == "201" ]]; then
            ok "Content pack installed — streams, alerts, dashboards, inputs, notifications restored"
        else
            warn "Install returned HTTP $INSTALL_CODE — verify in: System → Content Packs"
        fi
    else
        warn "Could not resolve content pack ID — install manually via System → Content Packs"
    fi
fi

# Give inputs a moment to start listening
sleep 3

# Verify at least one input exists before starting the generator
INPUT_COUNT=$(curl -s -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
    "$GRAYLOG_URL/api/system/inputs" 2>/dev/null | \
    python3 -c "import sys, json; print(json.load(sys.stdin).get('total', 0))" 2>/dev/null || echo "0")

if [ "$INPUT_COUNT" = "0" ]; then
    warn "No Graylog inputs configured — logs will not be ingested until you add one."
else
    ok "$INPUT_COUNT Graylog input(s) configured"
fi

# ─────────────────────────────────────────
# Step 7 — Start log generator and verify logs are flowing
# ─────────────────────────────────────────
step "[7/8] Starting log generator and verifying end-to-end flow..."

info "Installing Python dependencies..."
pip3 install requests --break-system-packages --quiet 2>/dev/null || \
pip3 install requests --quiet 2>/dev/null || \
python3 -m pip install requests --quiet 2>/dev/null || \
warn "Could not install requests — generator may fail"
ok "Python dependencies ready"

mkdir -p "$LOGS_DIR"

# Kill any existing generator to avoid duplicates
pkill -f "log_generator.py" 2>/dev/null || true
sleep 1

# Use universal search — works across Graylog versions
get_message_count() {
    curl -s -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
        -H "Accept: application/json" \
        "$GRAYLOG_URL/api/search/universal/relative?query=*&range=300&limit=1" 2>/dev/null | \
    python3 -c "import sys, json; print(json.load(sys.stdin).get('total_results', 0))" 2>/dev/null || echo "0"
}

BASELINE_COUNT=$(get_message_count)
info "Baseline message count: $BASELINE_COUNT"

# Start the generator
info "Starting log generator in background..."
nohup python3 "$SCRIPTS_DIR/log_generator.py" > "$GENERATOR_LOG" 2>&1 &
GENERATOR_PID=$!
sleep 3


# Start geomap
info "Starting live attack map in background..."
pip3 install flask --break-system-packages --quiet 2>/dev/null || true
pkill -f "geomap.py" 2>/dev/null || true
sleep 1
nohup python3 "$(dirname "$0")/geomap/geomap.py" > "$(dirname "$0")/logs/geomap.log" 2>&1 &
GEOMAP_PID=$!
sleep 2
if kill -0 "$GEOMAP_PID" 2>/dev/null; then
    ok "Live attack map started — http://localhost:8888"
else
    echo -e "${YELLOW}[WARN] Geomap may not have started. Check: logs/geomap.log${NC}"
fi


# Check generator survived startup
if ! kill -0 "$GENERATOR_PID" 2>/dev/null; then
    echo ""
    warn "Log generator crashed on startup. Last 20 lines of generator log:"
    echo "---"
    tail -20 "$GENERATOR_LOG" 2>/dev/null || echo "(log file is empty)"
    echo "---"
    fail "Cannot continue — fix the generator and re-run bootstrap."
fi
ok "Log generator running (PID: $GENERATOR_PID)"

# Smoke test — wait up to 30 seconds for new messages
info "Verifying logs are reaching Graylog..."
SMOKE_RETRIES=10
SMOKE_COUNT=0
LOGS_FLOWING=0

while [ $SMOKE_COUNT -lt $SMOKE_RETRIES ]; do
    sleep 3
    CURRENT_COUNT=$(get_message_count)

    if [ "$CURRENT_COUNT" -gt "$BASELINE_COUNT" ] 2>/dev/null; then
        NEW_MESSAGES=$((CURRENT_COUNT - BASELINE_COUNT))
        ok "Logs flowing: $NEW_MESSAGES new messages ingested (total: $CURRENT_COUNT)"
        LOGS_FLOWING=1
        break
    fi

    SMOKE_COUNT=$((SMOKE_COUNT + 1))
    printf "."
done
echo ""

if [ $LOGS_FLOWING -ne 1 ]; then
    warn "No new messages detected after 30 seconds. Possible causes:"
    echo "       • Content pack inputs not started — check System → Inputs in Graylog UI"
    echo "       • Log generator sending to wrong port — check: cat $GENERATOR_LOG"
    echo "       • Firewall blocking localhost:1514 or localhost:12201"
    echo ""
    echo "       Last 10 lines of generator log:"
    echo "       ---"
    tail -10 "$GENERATOR_LOG" 2>/dev/null | sed 's/^/       /'
    echo "       ---"
fi

# ─────────────────────────────────────────
# Step 8 — Start OmniLog AI assistant
# ─────────────────────────────────────────
step "[8/8] Starting OmniLog AI assistant..."

OMNILOG_DIR="$(dirname "$0")/omnilog"
ML_LOG="$LOGS_DIR/ml_service.log"
OMNILOG_API_LOG="$LOGS_DIR/omnilog_api.log"
OMNILOG_UI_LOG="$LOGS_DIR/omnilog_ui.log"

info "Installing OmniLog Python dependencies..."
pip3 install -r "$(dirname "$0")/ml/requirements.txt" --break-system-packages --quiet 2>/dev/null || \
pip3 install -r "$(dirname "$0")/ml/requirements.txt" --quiet 2>/dev/null || \
python3 -m pip install -r "$(dirname "$0")/ml/requirements.txt" --quiet 2>/dev/null || \
warn "Could not install OmniLog dependencies — run: pip3 install -r ml/requirements.txt"
ok "OmniLog Python dependencies ready"

# Check model file exists
MODEL_FILE="$(dirname "$0")/models/catnip_severity_model.pkl"
if [ ! -f "$MODEL_FILE" ]; then
    warn "ML model not found: $MODEL_FILE"
    warn "Skipping ML service — train the model in notebooks/catnip_ml_trainer.ipynb and copy the .pkl to models/"
    ML_SKIP=1
else
    ok "ML model found"
    ML_SKIP=0
fi

# Kill any stale instances
pkill -f "ml_service.py" 2>/dev/null || true
pkill -f "omnilog_api.py" 2>/dev/null || true
sleep 1

if [ "$ML_SKIP" -eq 0 ]; then
    info "Starting ML service (port 5001)..."
    nohup python3 "$SCRIPTS_DIR/ml_service.py" > "$ML_LOG" 2>&1 &
    ML_PID=$!
    sleep 3
    if kill -0 "$ML_PID" 2>/dev/null; then
        ok "ML service running (PID: $ML_PID)"
    else
        warn "ML service failed to start. Check: $ML_LOG"
    fi
fi

info "Starting OmniLog API (port 5002)..."
nohup python3 "$SCRIPTS_DIR/omnilog_api.py" > "$OMNILOG_API_LOG" 2>&1 &
OMNILOG_API_PID=$!
sleep 3

if kill -0 "$OMNILOG_API_PID" 2>/dev/null; then
    ok "OmniLog API running (PID: $OMNILOG_API_PID)"
else
    warn "OmniLog API failed to start. Check: $OMNILOG_API_LOG"
fi

OMNILOG_UI_PID=""
if [ -d "$OMNILOG_DIR" ] && command -v node &>/dev/null; then
    if [ ! -d "$OMNILOG_DIR/node_modules" ]; then
        info "Installing OmniLog frontend dependencies (first run)..."
        (cd "$OMNILOG_DIR" && npm install --silent 2>/dev/null) || warn "npm install failed"
    fi
    info "Starting OmniLog frontend (port 5173)..."
    nohup bash -c "cd '$OMNILOG_DIR' && node_modules/.bin/vite --port 5173" > "$OMNILOG_UI_LOG" 2>&1 &
    OMNILOG_UI_PID=$!
    sleep 4
    if kill -0 "$OMNILOG_UI_PID" 2>/dev/null; then
        ok "OmniLog UI running (PID: $OMNILOG_UI_PID) — http://localhost:5173"
    else
        warn "OmniLog UI failed to start. Check: $OMNILOG_UI_LOG"
    fi
else
    warn "Node.js not found — skipping OmniLog frontend. Install from https://nodejs.org"
fi

# ─────────────────────────────────────────
# Done
# ─────────────────────────────────────────
echo ""
echo "============================================================="
if [ $LOGS_FLOWING -eq 1 ]; then
    echo -e "${GREEN}   Bootstrap complete — SIEM is fully operational!${NC}"
else
    echo -e "${YELLOW}   Bootstrap complete — but verify logs manually.${NC}"
fi
echo "============================================================="
echo ""
echo "  Graylog UI:      $GRAYLOG_URL"
echo "  Username:        admin"
echo "  Password:        (from GRAYLOG_ADMIN_PASSWORD in .env)"
echo "  Attack Map:      http://localhost:8888"
echo "  OmniLog UI:      http://localhost:5173"
echo "  OmniLog API:     http://localhost:5002"
echo "  ML Service:      http://localhost:5001"
echo ""
echo "  Log generator:   running in background (PID: $GENERATOR_PID)"
echo "  Generator logs:  $GENERATOR_LOG"
echo ""
echo "  To generate a security report:"
echo "    python3 scripts/report_generator.py"
echo ""
echo "  To stop everything:"
echo "    pkill -f log_generator.py"
echo "    pkill -f geomap.py"
echo "    pkill -f ml_service.py"
echo "    pkill -f omnilog_api.py"
echo "    pkill -f vite"
echo "    docker compose down"
echo ""
echo "============================================================="
echo ""
