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
fail() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }
step() { echo -e "\n${CYAN}$1${NC}"; }

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
GRAYLOG_URL="http://localhost:9000"
GRAYLOG_USER="admin"
CONTENT_PACK_FILE="$(dirname "$0")/content-packs/catnip-siem-pack.json"
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
ok "Docker Compose found: $(docker compose version)"

if ! command -v python3 &>/dev/null; then
    fail "Python3 not found. Please install Python 3 from https://python.org and try again."
fi
ok "Python3 found: $(python3 --version)"

# ─────────────────────────────────────────
# Step 3 — Set vm.max_map_count (Linux/WSL only)
# ─────────────────────────────────────────
step "[3/7] Configuring system settings..."

if [[ "$OS" == "wsl" || "$OS" == "linux" ]]; then
    info "Setting vm.max_map_count=262144 (required by OpenSearch)..."
    sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1
    if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf 2>/dev/null; then
        echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf >/dev/null
        ok "vm.max_map_count set permanently in /etc/sysctl.conf"
    else
        ok "vm.max_map_count already permanent in /etc/sysctl.conf"
    fi
else
    ok "macOS — vm.max_map_count not required (Docker Desktop manages this)"
fi

# ─────────────────────────────────────────
# Step 4 — Check .env exists
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
    echo "    GRAYLOG_HTTP_EXTERNAL_URI"
    echo "    OPENSEARCH_ADMIN_PASSWORD"
    echo "    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD"
    echo ""
    exit 1
fi
ok ".env file found"

# Load GRAYLOG_PASS from .env for API calls
if [ -z "$GRAYLOG_PASS" ]; then
    GRAYLOG_PASS=$(grep "^GRAYLOG_ROOT_PASSWORD_SHA2=" .env | cut -d'=' -f2-)
    # We need the plain text password for API calls — prompt if not set
    if [ -z "$GRAYLOG_PASS" ]; then
        echo ""
        echo -e "${YELLOW}Enter your Graylog admin password (plain text, for API calls):${NC}"
        read -s GRAYLOG_PASS
        echo ""
    fi
fi

# ─────────────────────────────────────────
# Step 5 — Start Docker stack
# ─────────────────────────────────────────
step "[5/7] Starting Docker containers..."

info "Running docker compose up -d..."
docker compose up -d

echo ""
info "Waiting for Graylog to become healthy (this takes 1-2 minutes)..."

RETRIES=60
COUNT=0
while [ $COUNT -lt $RETRIES ]; do
    STATUS=$(docker compose ps --format json 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if 'graylog' in d.get('Name','').lower() or 'graylog' in d.get('Service','').lower():
            print(d.get('Health', d.get('Status', '')))
    except: pass
" 2>/dev/null || echo "")

    if echo "$STATUS" | grep -qi "healthy"; then
        ok "Graylog is healthy"
        break
    fi

    COUNT=$((COUNT + 1))
    printf "."
    sleep 3

    if [ $COUNT -ge $RETRIES ]; then
        echo ""
        fail "Graylog did not become healthy after $((RETRIES * 3)) seconds.\nRun: docker compose logs graylog"
    fi
done
echo ""

# ─────────────────────────────────────────
# Step 6 — Install content pack
# ─────────────────────────────────────────
step "[6/7] Installing Graylog content pack..."

if [ ! -f "$CONTENT_PACK_FILE" ]; then
    echo -e "${YELLOW}[SKIP] Content pack not found at: $CONTENT_PACK_FILE${NC}"
    echo "       You can import it manually: System → Content Packs → Upload"
else
    info "Uploading content pack to Graylog API..."

    # Upload the content pack
    UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" \
        -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
        -H "X-Requested-By: bootstrap" \
        -H "Content-Type: application/json" \
        -X POST \
        "$GRAYLOG_URL/api/system/content_packs" \
        -d @"$CONTENT_PACK_FILE" 2>/dev/null)

    HTTP_CODE=$(echo "$UPLOAD_RESPONSE" | tail -1)
    RESPONSE_BODY=$(echo "$UPLOAD_RESPONSE" | head -1)

    if [[ "$HTTP_CODE" == "201" || "$HTTP_CODE" == "200" ]]; then
        ok "Content pack uploaded successfully"

        # Extract content pack ID and install it
        PACK_ID=$(echo "$RESPONSE_BODY" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('id', d.get('content_pack_id', '')))
except: pass
" 2>/dev/null)

        if [ -n "$PACK_ID" ]; then
            info "Installing content pack (ID: $PACK_ID)..."
            INSTALL_RESPONSE=$(curl -s -w "\n%{http_code}" \
                -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
                -H "X-Requested-By: bootstrap" \
                -H "Content-Type: application/json" \
                -X POST \
                "$GRAYLOG_URL/api/system/content_packs/$PACK_ID/1/installations" \
                -d '{"parameters":{},"comment":"Installed by bootstrap script"}' 2>/dev/null)

            INSTALL_CODE=$(echo "$INSTALL_RESPONSE" | tail -1)
            if [[ "$INSTALL_CODE" == "200" || "$INSTALL_CODE" == "201" ]]; then
                ok "Content pack installed — streams, alerts, dashboards, notifications restored"
            else
                echo -e "${YELLOW}[WARN] Content pack upload succeeded but install returned HTTP $INSTALL_CODE${NC}"
                echo "       Install manually: System → Content Packs → find 'Catnip Games SIEM' → Install"
            fi
        else
            echo -e "${YELLOW}[WARN] Could not extract content pack ID from response${NC}"
            echo "       Install manually: System → Content Packs → find 'Catnip Games SIEM' → Install"
        fi
    elif [[ "$HTTP_CODE" == "400" ]]; then
        echo -e "${YELLOW}[SKIP] Content pack already exists in Graylog${NC}"
        ok "Skipping upload — content pack already installed"
    else
        echo -e "${YELLOW}[WARN] Content pack upload returned HTTP $HTTP_CODE${NC}"
        echo "       Install manually: System → Content Packs → Upload"
    fi
fi

# ─────────────────────────────────────────
# Step 7 — Install Python deps + start generator
# ─────────────────────────────────────────
step "[7/7] Installing Python dependencies and starting log generator..."

pip3 install requests --break-system-packages --quiet 2>/dev/null || \
pip3 install requests --quiet 2>/dev/null || \
python3 -m pip install requests --quiet 2>/dev/null
ok "Python requests library installed"

mkdir -p "$LOGS_DIR"

# Kill any existing generator process
pkill -f "log_generator.py" 2>/dev/null || true
sleep 1

# Start generator in background
nohup python3 "$SCRIPTS_DIR/log_generator.py" > "$GENERATOR_LOG" 2>&1 &
GENERATOR_PID=$!
sleep 2

if kill -0 "$GENERATOR_PID" 2>/dev/null; then
    ok "Log generator started (PID: $GENERATOR_PID)"
else
    echo -e "${YELLOW}[WARN] Log generator may not have started. Check: $GENERATOR_LOG${NC}"
fi

# ─────────────────────────────────────────
# Done
# ─────────────────────────────────────────
echo ""
echo "============================================================="
echo -e "${GREEN}   Bootstrap complete!${NC}"
echo "============================================================="
echo ""
echo "  Graylog UI:      $GRAYLOG_URL"
echo "  Username:        admin"
echo "  Password:        (from your .env file)"
echo ""
echo "  Log generator:   running in background"
echo "  Generator logs:  $GENERATOR_LOG"
echo ""
echo "  To generate a security report:"
echo "    export GRAYLOG_PASS=your_password"
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
