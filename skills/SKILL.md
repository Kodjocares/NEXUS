# NEXUS — Autonomous OSINT & Threat Intelligence

## Description
NEXUS is a multi-domain autonomous threat intelligence system. It performs
multi-source OSINT recon, calculates weighted threat scores, generates
interactive link graphs, and reports to Notion/Obsidian — all triggered
via natural language commands from WhatsApp or Telegram.

## Trigger phrases
- nexus
- scan, recon, osint
- threat score, risk score
- virustotal, shodan, censys, abuseipdb
- cve, vulnerability, exploit
- link graph, graph, map
- report, notion, obsidian
- watch, monitor, alert, track
- pr list, github, review, deploy

## Capabilities
- 6-layer OSINT: VirusTotal, Shodan, Censys, AbuseIPDB, CVE/NVD, WHOIS/DNS
- Weighted 0–100 threat score with CLEAN/LOW/MEDIUM/HIGH/CRITICAL verdict
- Maltego-style interactive D3 link graph (auto URL returned to user)
- Automated reports pushed to Notion database + Obsidian vault
- GitHub PR/issue management and code review
- Persistent monitoring watchlist with delta-score alerting
- Proactive WhatsApp/Telegram alerts when threat scores change

## Execution
Route through: bash ~/.openclaw/skills/nexus/tools/dispatch.sh "$INPUT"

## Examples
- "nexus scan 185.220.101.47"       → full recon + threat score + graph URL
- "nexus cve log4j"                 → top CVEs for log4j with EPSS scores
- "nexus report evil.com"           → push to Notion + Obsidian
- "nexus watch ip 1.2.3.4"         → add to monitoring watchlist
- "nexus pr list"                   → list open GitHub PRs
- "nexus shodan apache port:80"     → Shodan search query

## Setup
See README.md for full configuration.
Requires: .env file with API keys (see .env.example)
