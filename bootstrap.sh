#!/bin/bash
# =============================================================
# Catnip Games SIEM - Bootstrap Script
# Supports: Mac, Linux, WSL (Windows Subsystem for Linux)
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
step "[1/7] Detecting operating system..."

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
step "[2/7] Checking dependencies..."

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
step "[3/7] Configuring system settings..."

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
# Step 4 — Check .env and load Graylog password
# ─────────────────────────────────────────
step "[4/7] Checking environment configuration..."

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

# Load plaintext admin password from .env (NOT the SHA2 hash)
if [ -z "$GRAYLOG_PASS" ]; then
    GRAYLOG_PASS=$(grep "^GRAYLOG_ADMIN_PASSWORD=" .env | cut -d'=' -f2- | tr -d '"'"'")
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
step "[5/7] Starting Docker containers..."

info "Running docker compose up -d..."
docker compose up -d

echo ""
info "Waiting for Graylog to become ready (this takes 1-2 minutes)..."

RETRIES=60
COUNT=0
READY=0

while [ $COUNT -lt $RETRIES ]; do
    # Hit the lbstatus endpoint — returns "ALIVE" when Graylog is ready
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
# Step 6 — Install content pack (idempotent)
# ─────────────────────────────────────────
step "[6/7] Installing Graylog content pack..."

if [ ! -f "$CONTENT_PACK_FILE" ]; then
    warn "Content pack not found at: $CONTENT_PACK_FILE"
    echo "       You can import it manually: System → Content Packs → Upload"
else
    # Check if content pack already exists (idempotent)
    info "Checking for existing content pack..."
    EXISTING=$(curl -s -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
        -H "X-Requested-By: bootstrap" \
        "$GRAYLOG_URL/api/system/content_packs" 2>/dev/null)

    EXISTING_PACK_ID=$(echo "$EXISTING" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    packs = data.get('content_packs', [])
    for p in packs:
        if p.get('name') == '$CONTENT_PACK_NAME':
            print(p.get('id', ''))
            break
except Exception:
    pass
" 2>/dev/null)

    if [ -n "$EXISTING_PACK_ID" ]; then
        ok "Content pack already exists (ID: $EXISTING_PACK_ID) — skipping upload"
        PACK_ID="$EXISTING_PACK_ID"
    else
        info "Uploading content pack..."
        UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" \
            -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
            -H "X-Requested-By: bootstrap" \
            -H "Content-Type: application/json" \
            -X POST \
            "$GRAYLOG_URL/api/system/content_packs" \
            -d @"$CONTENT_PACK_FILE" 2>/dev/null)

        HTTP_CODE=$(echo "$UPLOAD_RESPONSE" | tail -1)
        RESPONSE_BODY=$(echo "$UPLOAD_RESPONSE" | sed '$d')

        if [[ "$HTTP_CODE" == "201" || "$HTTP_CODE" == "200" ]]; then
            ok "Content pack uploaded"
            PACK_ID=$(echo "$RESPONSE_BODY" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('id', d.get('content_pack_id', '')))
except: pass
" 2>/dev/null)
        else
            warn "Upload returned HTTP $HTTP_CODE — install manually via System → Content Packs"
            PACK_ID=""
        fi
    fi

    # Install the content pack (safe to re-run — Graylog will no-op if already installed)
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
            warn "Install returned HTTP $INSTALL_CODE — may already be installed. Verify in: System → Content Packs"
        fi
    fi
fi

# Give inputs a moment to start listening
sleep 3

# ─────────────────────────────────────────
# Step 7 — Start log generator and verify logs are flowing
# ─────────────────────────────────────────
step "[7/7] Starting log generator and verifying end-to-end flow..."

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

# Capture baseline message count so we can detect new logs arriving
BASELINE_COUNT=$(curl -s -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
    "$GRAYLOG_URL/api/count/total" 2>/dev/null | \
    python3 -c "import sys, json; print(json.load(sys.stdin).get('events', 0))" 2>/dev/null || echo "0")

info "Baseline message count: $BASELINE_COUNT"

# Start the generator
info "Starting log generator in background..."
nohup python3 "$SCRIPTS_DIR/log_generator.py" > "$GENERATOR_LOG" 2>&1 &
GENERATOR_PID=$!
sleep 3

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

# Smoke test — wait up to 30 seconds for new messages to arrive
info "Verifying logs are reaching Graylog..."
SMOKE_RETRIES=10
SMOKE_COUNT=0
LOGS_FLOWING=0

while [ $SMOKE_COUNT -lt $SMOKE_RETRIES ]; do
    sleep 3
    CURRENT_COUNT=$(curl -s -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
        "$GRAYLOG_URL/api/count/total" 2>/dev/null | \
        python3 -c "import sys, json; print(json.load(sys.stdin).get('events', 0))" 2>/dev/null || echo "0")

    if [ "$CURRENT_COUNT" -gt "$BASELINE_COUNT" ]; then
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
echo ""
echo "  Log generator:   running in background (PID: $GENERATOR_PID)"
echo "  Generator logs:  $GENERATOR_LOG"
echo ""
echo "  To generate a security report:"
echo "    python3 scripts/report_generator.py"
echo ""
echo "  To stop the log generator:"
echo "    pkill -f log_generator.py"
echo ""
echo "  To stop all containers:"
echo "    docker compose down"
echo ""
echo "============================================================="
echo ""
