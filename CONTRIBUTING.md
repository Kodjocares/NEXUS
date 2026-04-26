# Contributing to NEXUS

Thank you for your interest in contributing. This document covers how to set up a dev environment, the contribution workflow, and guidelines for adding new tools.

---

## Development Setup

```bash
git clone https://github.com/Kodjocares/nexus.git
cd nexus

# Install deps in a virtual env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Copy env
cp .env.example .env
# Fill in at least GRAPH_SERVER_SECRET for local dev
```

Run individual tools without the bot:

```bash
source .env  # or export vars manually
bash tools/osint.sh vt 8.8.8.8
bash tools/dispatch.sh "scan 8.8.8.8"
```

---

## Adding a New OSINT Source

All OSINT sources live in `tools/osint.sh`. To add a new one:

1. Add a `run_<name>()` function following the existing pattern
2. Add it to the `case "$SOURCE" in` block at the bottom
3. Call it from `run_all()` if it should be part of full recon
4. Wire it into `tools/dispatch.sh` with a keyword trigger
5. Add the API key to `.env.example` with documentation
6. Add a test case to `.github/workflows/ci.yml`

---

## Contribution Workflow

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Run the linter: `shellcheck tools/*.sh` and `flake8 bot/ server/`
5. Commit with a conventional commit message: `feat:`, `fix:`, `docs:`, `chore:`
6. Push and open a pull request against `main`

---

## Production Setup on macOS (launchd)

Create `~/Library/LaunchAgents/com.nexus.bot.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.nexus.bot</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/path/to/nexus/bot/nexus_bot.py</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>WorkingDirectory</key>
  <string>/path/to/nexus</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/yourname/.openclaw/nexus_bot.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/yourname/.openclaw/nexus_bot_err.log</string>
</dict>
</plist>
```

```bash
# Load it
launchctl load ~/Library/LaunchAgents/com.nexus.bot.plist

# Check status
launchctl list | grep nexus

# Unload
launchctl unload ~/Library/LaunchAgents/com.nexus.bot.plist
```

Create a second plist for `graph_server.py` following the same pattern.

---

## Code Style

- Shell: POSIX-compatible where possible, `shellcheck`-clean
- Python: PEP8, max line length 120, `flake8`-clean
- No hardcoded secrets — always read from environment
- All new tools must handle missing API keys gracefully with a clear error message

---

## Security

- Never commit `.env` or any file containing real API keys
- The `.gitignore` already excludes `.env`
- Report security issues privately via GitHub Security Advisories, not as public issues
