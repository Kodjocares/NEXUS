# ⬡ NEXUS

<div align="center">

![NEXUS Banner](https://img.shields.io/badge/NEXUS-Autonomous_OSINT-e24b4a?style=for-the-badge&logo=target&logoColor=white)

[![CI](https://github.com/Kodjocares/nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/Kodjocares/nexus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-378add.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776ab?logo=python&logoColor=white)](https://python.org)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-5dcaa5)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Skill-7f77dd)](https://github.com/steipete/openclaw)

**Autonomous multi-domain OSINT and threat intelligence system**
Powered by Claude · Controlled via WhatsApp and Telegram · Runs persistently via OpenClaw

</div>

---

## What is NEXUS?

NEXUS is a self-contained intelligence platform you control from your phone. Send a message to your Telegram bot or WhatsApp number, and NEXUS autonomously runs multi-source OSINT recon, calculates a weighted threat score, generates an interactive link graph you can tap open in your browser, and pushes structured reports to Notion and Obsidian — all without touching a terminal.

```
You (WhatsApp / Telegram)
         |
         v
   nexus_bot.py  <-----------------------------------------+
         |                                                  |
         v                                                  |
   dispatch.sh                                    proactive alerts
         |                                        (score delta, events)
    +----+------------------------+                         |
    v             v               v                         |
Security        Dev            Monitor --------------------+
 Agent          Agent           Agent
    |             |
    v             v
 osint.sh      github.sh
  |-- VirusTotal
  |-- Shodan
  |-- Censys
  |-- AbuseIPDB
  +-- CVE/NVD + EPSS
         |
         v
 threat_score.sh --> weighted 0-100 score
         |
         v
   graph.sh --> POST --> graph_server.py --> URL sent to phone
         |
         v
   report.sh --> Notion page + Obsidian vault note
```

---

## Features

| Feature | Detail |
|---|---|
| 🔬 **6-layer OSINT** | VirusTotal, Shodan, Censys, AbuseIPDB, CVE/NVD, WHOIS/DNS |
| 🧮 **Threat scoring** | Weighted 0-100 with CLEAN / LOW / MEDIUM / HIGH / CRITICAL |
| 🕸 **Link graph** | Auto-rendered interactive D3 graph URL sent back in chat |
| 📲 **Dual bot** | Telegram Bot API + WhatsApp via Twilio |
| 📋 **Auto-reports** | Notion database page + Obsidian vault note per scan |
| 👁 **Monitoring** | Watchlist with 15-min cron re-scans and delta alerting |
| 🤖 **Dev agent** | GitHub PR/issue management, code review summaries |
| 🔌 **OpenClaw skill** | Drop-in ClawHub skill for persistent autonomous use |

---

## Project Structure

```
nexus/
├── bot/
│   └── nexus_bot.py           Telegram + WhatsApp unified bot
├── server/
│   └── graph_server.py        Flask: stores graph JSON, serves D3 pages
├── tools/
│   ├── osint.sh               All 5 OSINT engines in one file
│   ├── dispatch.sh            Master command router
│   ├── recon.sh               Full 6-layer recon runner
│   ├── threat_score.sh        Weighted score aggregator
│   ├── graph.sh               Link graph JSON builder
│   ├── report.sh              Notion + Obsidian reporter
│   ├── monitor.sh             Watchlist + cron + alerting
│   └── github.sh              GitHub dev automation
├── agents/
│   ├── orchestrator.md        Master routing prompt
│   ├── security.md            Security agent prompt
│   ├── dev.md                 Dev agent prompt
│   └── monitor.md             Monitor agent prompt
├── skills/
│   └── SKILL.md               OpenClaw / ClawHub skill definition
├── .github/
│   └── workflows/ci.yml       Lint + test CI pipeline
├── .env.example               All required env vars documented
├── install.sh                 One-command installer
├── requirements.txt           Python dependencies
├── CONTRIBUTING.md
└── LICENSE
```

---

## Quick Start

### Prerequisites

- macOS or Linux
- Python 3.10+
- `curl`, `dig`, `whois` (standard on macOS)
- `gh` CLI for Dev agent: `brew install gh`
- Telegram bot token **or** Twilio account for WhatsApp

### 1 — Clone and install

```bash
git clone https://github.com/Kodjocares/nexus.git
cd nexus
bash install.sh
```

### 2 — Configure

```bash
nano .env
```

Fill in at minimum: one bot platform, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `GRAPH_SERVER_URL`, `GRAPH_SERVER_SECRET`.

### 3 — Start the graph server

```bash
python3 server/graph_server.py
```

For external access from your phone:

```bash
ngrok http 5555
# Copy the https://xxxx.ngrok.io URL into GRAPH_SERVER_URL in .env
```

### 4 — Start the bot

```bash
python3 bot/nexus_bot.py
```

### 5 — Test it

Send this to your Telegram bot or WhatsApp number:

```
nexus scan 8.8.8.8
```

---

## Configuration Reference

### Bot platforms

| Variable | Description | Where to get it |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token | [@BotFather](https://t.me/botfather) |
| `TELEGRAM_CHAT_ID` | Your chat ID | [@userinfobot](https://t.me/userinfobot) |
| `TWILIO_ACCOUNT_SID` | Account SID | [console.twilio.com](https://console.twilio.com) |
| `TWILIO_AUTH_TOKEN` | Auth token | [console.twilio.com](https://console.twilio.com) |
| `TWILIO_WHATSAPP_FROM` | Sandbox number | Twilio WhatsApp sandbox |
| `WHATSAPP_TO` | Your number | `+358XXXXXXXXX` format |

### OSINT APIs

| Variable | Free tier | Sign up |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | 500 req/day | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| `SHODAN_API_KEY` | 100 credits/month | [account.shodan.io](https://account.shodan.io) |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | 250 queries/month | [search.censys.io/register](https://search.censys.io/register) |
| `ABUSEIPDB_API_KEY` | 1,000 checks/day | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |

CVE/NVD lookups are free with no key required.

### Reporting (optional)

| Variable | Description |
|---|---|
| `NOTION_API_TOKEN` | From [notion.so/my-integrations](https://www.notion.so/my-integrations) |
| `NOTION_DATABASE_ID` | ID from your Notion database URL |
| `OBSIDIAN_VAULT_PATH` | Absolute path e.g. `/Users/you/Documents/Vault` |

### Graph server

| Variable | Description |
|---|---|
| `GRAPH_SERVER_URL` | Reachable URL e.g. `https://xxxx.ngrok.io` |
| `GRAPH_SERVER_PORT` | Port (default: `5555`) |
| `GRAPH_SERVER_SECRET` | Random string to protect `/graph/store` |

### GitHub

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` | Token with `repo` + `read:user` scopes |

---

## Bot Commands

```
nexus scan <ip|domain>           Full 6-layer recon + score + graph link
nexus score <ip|domain>          Threat score only
nexus graph <ip|domain>          Interactive link graph URL

nexus vt <ip|domain|hash|url>    VirusTotal
nexus shodan <ip|query>          Shodan host / search
nexus censys <ip|domain|query>   Censys host / search
nexus abuse <ip>                 AbuseIPDB
nexus cve CVE-2024-1234          CVE detail + EPSS score
nexus cve log4j                  CVE keyword search

nexus report <target>            Push to Notion + Obsidian
nexus report notion <target>     Notion only
nexus report obsidian <target>   Obsidian only

nexus pr list                    Open pull requests
nexus issue list                 Open issues

nexus watch ip <ip>              Add to watchlist
nexus watch domain <domain>      Add to watchlist
nexus watch repo <user/repo>     Watch GitHub repo
nexus monitor list               Active watches

nexus status                     System health
nexus help                       Full command reference
```

---

## Monitoring and Alerts

```bash
bash tools/monitor.sh watch ip 185.220.101.47
bash tools/monitor.sh watch domain suspicious.ru
bash tools/monitor.sh watch repo Kodjocares/nexus
bash tools/monitor.sh cron      # install 15-min cron job
bash tools/monitor.sh list      # show active watches
```

When a threat score changes by 20+ points, NEXUS sends a proactive alert to both platforms:

```
NEXUS ALERT [a3f92b1c]
Target : 185.220.101.47
Score  : 34.0 -> 71.5 (delta 37.5)
Risk   : HIGH
Time   : 2025-03-15 14:22 UTC
```

---

## OpenClaw Integration

```bash
cp skills/SKILL.md ~/.openclaw/skills/nexus/SKILL.md
```

NEXUS is then available as a ClawHub skill and triggered automatically by keywords: `scan`, `recon`, `cve`, `threat`, `shodan`, etc.

---

## Production Deployment (macOS)

```bash
# With PM2
npm install -g pm2
pm2 start "python3 bot/nexus_bot.py" --name nexus-bot
pm2 start "python3 server/graph_server.py" --name nexus-graph
pm2 save && pm2 startup
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Disclaimer

NEXUS is for authorized security research and defensive use only. Never scan targets without explicit permission. The authors are not responsible for misuse.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built by <a href="https://github.com/Kodjocares">@Kodjocares</a> with <a href="https://github.com/steipete/openclaw">OpenClaw</a> + <a href="https://claude.ai">Claude</a>
</div>
