#!/usr/bin/env bash
# ============================================================
# SentinelX — Linux Production Tool Installer
# ============================================================
# Run this script on your Ubuntu/Debian Linux production server
# before starting the SentinelX backend.
#
# Usage:
#   chmod +x setup_linux_tools.sh
#   sudo ./setup_linux_tools.sh
# ============================================================

set -euo pipefail

echo ""
echo "============================================"
echo "  SentinelX — Linux Tool Setup"
echo "============================================"
echo ""

# --- System packages ---
echo "[1/4] Installing system packages..."
apt-get update -qq
apt-get install -y \
    nmap \
    golang \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    libssl-dev

echo "✅ System packages installed"

# --- Go environment for Nuclei ---
echo ""
echo "[2/4] Setting up Go environment..."

export HOME=/root
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOBIN

# Check Go version
go version

echo "✅ Go environment ready"

# --- Nuclei ---
echo ""
echo "[3/4] Installing Nuclei vulnerability scanner..."

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Move to a system-wide location
if [ -f "$GOBIN/nuclei" ]; then
    cp "$GOBIN/nuclei" /usr/local/bin/nuclei
    echo "✅ Nuclei installed at /usr/local/bin/nuclei"
else
    echo "⚠️  Nuclei binary not found in GOBIN=$GOBIN"
    echo "    You may need to add GOBIN to PATH manually"
fi

# Download nuclei templates
echo "   Downloading Nuclei templates..."
nuclei -update-templates -silent || true
echo "✅ Nuclei templates downloaded"

# --- Verify installations ---
echo ""
echo "[4/4] Verifying tool installations..."

echo -n "   nmap:    "
nmap --version | head -1 || echo "NOT FOUND"

echo -n "   nuclei:  "
nuclei -version 2>&1 | head -1 || echo "NOT FOUND"

echo -n "   python3: "
python3 --version || echo "NOT FOUND"

# --- Python dependencies ---
echo ""
echo "[5/5] Installing Python dependencies..."

if [ -f "backend/requirements.txt" ]; then
    pip3 install -r backend/requirements.txt
    echo "✅ Python dependencies installed"
else
    echo "⚠️  backend/requirements.txt not found. Run from project root."
fi

echo ""
echo "============================================"
echo "  SentinelX Tool Setup Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Copy .env.example to .env and fill in API keys"
echo "  2. Start the database: docker compose -f docker/docker-compose.dev.yml up -d"
echo "  3. Start the API:      uvicorn backend.main:app --host 0.0.0.0 --port 8000"
echo ""
