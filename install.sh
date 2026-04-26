#!/bin/bash
# NEXUS — Installer
set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  NEXUS Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

OS=$(uname -s)

# ── Python deps ────────────────────────────────────────────────
echo ""
echo "[1/6] Installing Python dependencies..."
if command -v pip3 &>/dev/null; then
  pip3 install -r requirements.txt --quiet
  echo "  ✅ Python packages installed"
elif command -v pip &>/dev/null; then
  pip install -r requirements.txt --quiet
  echo "  ✅ Python packages installed"
else
  echo "  ❌ pip not found — install Python 3.10+"
  exit 1
fi

# ── Shell tools ────────────────────────────────────────────────
echo ""
echo "[2/6] Checking shell tools..."

check_tool() {
  if command -v "$1" &>/dev/null; then
    echo "  ✅ $1"
  else
    echo "  ⚠️  $1 not found — $2"
  fi
}

check_tool "curl"    "install via: brew install curl"
check_tool "dig"     "install via: brew install bind"
check_tool "whois"   "install via: brew install whois"
check_tool "python3" "install Python 3.10+ from python.org"
check_tool "gh"      "install via: brew install gh — needed for Dev agent"
check_tool "jq"      "install via: brew install jq — optional but recommended"

# ── chmod scripts ──────────────────────────────────────────────
echo ""
echo "[3/6] Setting script permissions..."
chmod +x tools/*.sh
echo "  ✅ tools/*.sh are executable"

# ── Create data dirs ───────────────────────────────────────────
echo ""
echo "[4/6] Creating data directories..."
mkdir -p ~/.openclaw/nexus_cache
mkdir -p ~/.openclaw/nexus_reports
mkdir -p ~/.openclaw/nexus_graphs
echo "  ✅ ~/.openclaw/nexus_* directories created"

# ── .env setup ────────────────────────────────────────────────
echo ""
echo "[5/6] Environment setup..."
if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "  ✅ .env created from .env.example"
  echo "  ⚠️  Edit .env and add your API keys before running"
else
  echo "  ✅ .env already exists"
fi

# ── OpenClaw skill install ─────────────────────────────────────
echo ""
echo "[6/6] OpenClaw skill..."
OPENCLAW_SKILLS=~/.openclaw/skills/nexus
if [ -d "$OPENCLAW_SKILLS" ]; then
  cp skills/SKILL.md "$OPENCLAW_SKILLS/SKILL.md"
  echo "  ✅ SKILL.md updated in $OPENCLAW_SKILLS"
else
  mkdir -p "$OPENCLAW_SKILLS"
  cp skills/SKILL.md "$OPENCLAW_SKILLS/SKILL.md"
  echo "  ✅ NEXUS skill installed to $OPENCLAW_SKILLS"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Installation complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Next steps:"
echo "  1. Edit .env with your API keys"
echo "  2. Start graph server:   python3 server/graph_server.py"
echo "  3. Start bot:            python3 bot/nexus_bot.py"
echo "  4. Install monitor cron: bash tools/monitor.sh cron"
echo "  5. Test:                 bash tools/dispatch.sh 'scan 8.8.8.8'"
echo ""
echo "  See README.md for full documentation."
echo ""
